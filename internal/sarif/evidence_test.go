package sarif

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func parseEvidence(t *testing.T, doc string) []RunEvidence {
	t.Helper()
	parsed, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return ExtractRunEvidence(parsed)
}

// OpenGrep's shape: semanticVersion, executionSuccessful always true, and
// errors as location-less notifications whose path is in the message.
func TestRunEvidenceOpenGrepNotifications(t *testing.T) {
	evidence := parseEvidence(t, `{"version":"2.1.0","runs":[{
	  "tool":{"driver":{"name":"Opengrep OSS","semanticVersion":"1.30.0"}},
	  "invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[
	    {"descriptor":{"id":"Timeout"},"level":"error","message":{"text":"Timeout when running java.lang.security.cmdi on src/main/java/Big.java:\n timeout after 5s"}},
	    {"descriptor":{"id":"Syntax error"},"level":"warning","message":{"text":"Syntax error at line src/Broken.java:12:\n unexpected token"}},
	    {"descriptor":{"id":"Rule parse error"},"level":"error","message":{"text":"Rule parse error in rule bad.rule:\n invalid pattern"}},
	    {"descriptor":{"id":"Timeout"},"level":"note","message":{"text":"Timeout when running r on ignored.java:\n x"}}
	  ]}],
	  "results":[{"ruleId":"r","message":{"text":"m"}}]}]}`)
	if len(evidence) != 1 {
		t.Fatalf("runs = %d", len(evidence))
	}
	got := evidence[0]
	if got.Producer != "opengrep oss" || got.Version != "1.30.0" || got.FindingCount != 1 {
		t.Fatalf("identity = %+v", got)
	}
	if got.Outcome != RunOutcomePartial {
		t.Fatalf("outcome = %s", got.Outcome)
	}
	want := []SkippedFile{{"src/main/java/Big.java", SkipReasonTimeout}, {"src/Broken.java", SkipReasonParseError}}
	if len(got.Skipped) != len(want) || got.Skipped[0] != want[0] || got.Skipped[1] != want[1] {
		t.Fatalf("skipped = %+v", got.Skipped)
	}
	if got.Detail != "Rule parse error in rule bad.rule" {
		t.Fatalf("detail = %q", got.Detail)
	}
}

func TestRunEvidenceOutcomes(t *testing.T) {
	evidence := parseEvidence(t, `{"version":"2.1.0","runs":[
	  {"tool":{"driver":{"name":"gosec","version":"2.22.0"}},"results":[]},
	  {"tool":{"driver":{"name":"CodeQL"}},"invocations":[{"executionSuccessful":false}],"results":[]},
	  {"tool":{"driver":{"name":"spotbugs"}},"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[
	    {"level":"error","message":{"text":"file too large"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"gen/Huge.java"}}}]}]}],"results":[]}
	]}`)
	if len(evidence) != 3 {
		t.Fatalf("runs = %d", len(evidence))
	}
	if evidence[0].Outcome != RunOutcomeCompleted || evidence[0].Version != "2.22.0" {
		t.Fatalf("no invocation must read as completed: %+v", evidence[0])
	}
	if evidence[1].Outcome != RunOutcomeFailed {
		t.Fatalf("executionSuccessful=false must fail: %+v", evidence[1])
	}
	if evidence[2].Outcome != RunOutcomePartial || len(evidence[2].Skipped) != 1 || evidence[2].Skipped[0] != (SkippedFile{"gen/Huge.java", SkipReasonTooLarge}) {
		t.Fatalf("located notification: %+v", evidence[2])
	}
}

func TestExtractFindingsTraceFiles(t *testing.T) {
	parsed, err := Parse(strings.NewReader(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"opengrep"}},"results":[{
	  "ruleId":"cmdi","message":{"text":"m"},
	  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"CommandExecutor.java"},"region":{"startLine":9}}}],
	  "codeFlows":[{"threadFlows":[{"locations":[
	    {"location":{"physicalLocation":{"artifactLocation":{"uri":"CommandController.java"}}}},
	    {"location":{"physicalLocation":{"artifactLocation":{"uri":"Request.java"}}}},
	    {"location":{"physicalLocation":{"artifactLocation":{"uri":"CommandController.java"}}}},
	    {"location":{"physicalLocation":{"artifactLocation":{"uri":"CommandExecutor.java"}}}}]}]}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ExtractFindings(parsed, "repo")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CommandController.java", "Request.java", "CommandExecutor.java"}
	if len(findings) != 1 || strings.Join(findings[0].TraceFiles, ",") != strings.Join(want, ",") {
		t.Fatalf("trace files = %v", findings[0].TraceFiles)
	}
}

// Real captures (Phase 5 POC, hibou-sample-project java/): the released
// OpenGrep misses the cross-file command injection; the interfile build finds
// it at the sink, with a code flow from the controller. The interfile alpha
// reports semanticVersion 1.30.0, so a version string cannot tell it from the
// 1.30.0 release: the scanner catalog pins binaries by digest.
func TestOpenGrepCaptures(t *testing.T) {
	load := func(name string) *Document {
		t.Helper()
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := Parse(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}

	released := load("opengrep-1.30.1-java.sarif")
	findings, err := ExtractFindings(released, "repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if strings.Contains(finding.RuleID, "command-injection") {
			t.Fatal("1.30.1 has no interfile taint: it must not find the cross-file flow")
		}
	}
	if evidence := ExtractRunEvidence(released); evidence[0].Version != "1.30.1" || evidence[0].Outcome != RunOutcomeCompleted {
		t.Fatalf("1.30.1 evidence = %+v", evidence[0])
	}

	interfile := load("opengrep-interfile-java.sarif")
	findings, err = ExtractFindings(interfile, "repo")
	if err != nil {
		t.Fatal(err)
	}
	var taint *Finding
	for i := range findings {
		if strings.Contains(findings[i].RuleID, "command-injection") {
			taint = &findings[i]
		}
	}
	if taint == nil {
		t.Fatal("interfile build must find the command injection")
	}
	if !strings.HasSuffix(taint.FilePath, "CommandExecutor.java") || taint.Fingerprint == "" {
		t.Fatalf("taint finding = %+v", taint)
	}
	traces := strings.Join(taint.TraceFiles, ",")
	if !strings.Contains(traces, "CommandController.java") || !strings.Contains(traces, "CommandExecutor.java") {
		t.Fatalf("trace files = %v", taint.TraceFiles)
	}
	if evidence := ExtractRunEvidence(interfile); evidence[0].Producer != "opengrep oss" || evidence[0].Version != "1.30.0" {
		t.Fatalf("interfile evidence = %+v", evidence[0])
	}
}
