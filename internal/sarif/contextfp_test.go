package sarif

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func contextSARIF(results string) []byte {
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[` + results + `]}]}`)
}

func gosecResult(line int, extra string) string {
	return `{"ruleId":"G304","message":{"text":"file inclusion"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"io.go"},"region":{"startLine":` + strconv.Itoa(line) + `}}}]` + extra + `}`
}

func readerFor(files map[string]string) SourceReader {
	return func(uri, _ string) ([]byte, error) {
		content, ok := files[uri]
		if !ok {
			return nil, errors.New("not found")
		}
		return []byte(content), nil
	}
}

func contextFingerprints(t *testing.T, data []byte, files map[string]string) []string {
	t.Helper()
	out, _, err := AddContextFingerprints(data, readerFor(files))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ExtractFindings(doc, "repo")
	if err != nil {
		t.Fatal(err)
	}
	fps := make([]string, len(findings))
	for i, finding := range findings {
		fps[i] = finding.Fingerprint
	}
	return fps
}

const ioGo = "package io\n\nfunc read(p string) {\n\tdata, _ := os.ReadFile(p)\n\t_ = data\n}\n"

// The point of the context hash: code added above the finding moves its line
// but keeps its identity.
func TestContextFingerprintSurvivesLineDrift(t *testing.T) {
	before := contextFingerprints(t, contextSARIF(gosecResult(4, "")), map[string]string{"io.go": ioGo})
	shifted := "// header\n// more\n" + ioGo
	after := contextFingerprints(t, contextSARIF(gosecResult(6, "")), map[string]string{"io.go": shifted})
	if before[0] != after[0] {
		t.Fatalf("fingerprint changed after drift: %s vs %s", before[0], after[0])
	}
	reindented := strings.Replace(ioGo, "\tdata, _ :=", "    data,  _ :=", 1)
	if got := contextFingerprints(t, contextSARIF(gosecResult(4, "")), map[string]string{"io.go": reindented}); got[0] != before[0] {
		t.Fatal("whitespace-only change re-keyed the finding")
	}
	edited := strings.Replace(ioGo, "os.ReadFile(p)", "os.ReadFile(clean(p))", 1)
	if got := contextFingerprints(t, contextSARIF(gosecResult(4, "")), map[string]string{"io.go": edited}); got[0] == before[0] {
		t.Fatal("editing the flagged line must change the identity")
	}
}

func TestContextFingerprintNumbersIdenticalContexts(t *testing.T) {
	src := "a\nb\nx := f()\nc\nd\na\nb\nx := f()\nc\nd\n"
	fps := contextFingerprints(t, contextSARIF(gosecResult(3, "")+","+gosecResult(8, "")), map[string]string{"io.go": src})
	if fps[0] == fps[1] {
		t.Fatal("identical contexts must get distinct identities")
	}
}

func TestContextFingerprintLeavesScannerFingerprintsAndUnreadableFiles(t *testing.T) {
	withFP := contextSARIF(gosecResult(4, `,"fingerprints":{"matchBasedId/v1":"abc"}`))
	out, added, err := AddContextFingerprints(withFP, readerFor(map[string]string{"io.go": ioGo}))
	if err != nil || added != 0 || !bytes.Equal(out, withFP) {
		t.Fatalf("document with fingerprints must pass through unchanged: added=%d err=%v", added, err)
	}
	missing := contextSARIF(gosecResult(4, ""))
	out, added, err = AddContextFingerprints(missing, readerFor(nil))
	if err != nil || added != 0 || !bytes.Equal(out, missing) {
		t.Fatalf("unreadable source must pass through unchanged: added=%d err=%v", added, err)
	}
}

func TestContextFingerprintResolvesArtifactIndexAndBaseID(t *testing.T) {
	data := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"spotbugs"}},
	  "originalUriBaseIds":{"SRCROOT":{"uri":"file:///src/"}},
	  "artifacts":[{"location":{"uri":"io.go","uriBaseId":"SRCROOT"}}],
	  "results":[{"ruleId":"X","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"index":0},"region":{"startLine":4}}}]}]}]}`)
	var gotBase string
	out, added, err := AddContextFingerprints(data, func(uri, base string) ([]byte, error) {
		gotBase = base
		return []byte(ioGo), nil
	})
	if err != nil || added != 1 || gotBase != "file:///src/" {
		t.Fatalf("added=%d base=%q err=%v", added, gotBase, err)
	}
	if !bytes.Contains(out, []byte(ContextFingerprintKey)) {
		t.Fatal("fingerprint not written")
	}
}

func TestRewriteArtifactURIs(t *testing.T) {
	doc := []byte(`{"runs":[{"tool":{"driver":{"name":"SpotBugs"}},
	  "artifacts":[{"location":{"uri":"com/a/X.java"}}],
	  "results":[{"ruleId":"R","locations":[{"physicalLocation":{"artifactLocation":{"uri":"com/a/X.java","uriBaseId":"SRC"},"region":{"startLine":3}}}],
	    "codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"com/a/Y.java"}}}}]}]}]}]}]}`)
	out, n, err := RewriteArtifactURIs(doc, func(uri, _ string) (string, bool) {
		return "java/src/main/java/" + uri, true
	})
	if err != nil || n != 3 {
		t.Fatalf("rewritten = %d, %v", n, err)
	}
	parsed, err := Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := ExtractFindings(parsed, "repo")
	if findings[0].FilePath != "java/src/main/java/com/a/X.java" || findings[0].TraceFiles[0] != "java/src/main/java/com/a/Y.java" {
		t.Fatalf("finding = %+v", findings[0])
	}
	if bytes.Contains(out, []byte(`"uriBaseId"`)) {
		t.Fatal("rewritten location must drop its uriBaseId")
	}
}
