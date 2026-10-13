package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// Q2: gitleaks-style SARIF carries the matched secret in region.snippet; the
// stored artifact must not.
func TestStripSnippetsRemovesEverySnippet(t *testing.T) {
	content := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{
		"ruleId":"aws-access-token","message":{"text":"aws-access-token has detected secret"},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.env"},
			"region":{"startLine":3,"snippet":{"text":"AKIAIOSFODNN7EXAMPLE"}},
			"contextRegion":{"startLine":2,"endLine":4,"snippet":{"text":"KEY=AKIAIOSFODNN7EXAMPLE"}}}}],
		"relatedLocations":[{"physicalLocation":{"region":{"startLine":9,"snippet":{"text":"REL-SECRET"}}}}],
		"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"region":{"startLine":1,"snippet":{"text":"FLOW-SECRET"}}}}}]}]}],
		"fixes":[{"artifactChanges":[{"replacements":[{"deletedRegion":{"startLine":3,"snippet":{"text":"FIX-SECRET"}}}]}]}],
		"properties":{"snippet":"kept: not a region","big":12345678901234567890}
	}]}]}`)

	stripped, err := StripSnippets(content)
	if err != nil {
		t.Fatalf("StripSnippets: %v", err)
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "REL-SECRET", "FLOW-SECRET", "FIX-SECRET"} {
		if bytes.Contains(stripped, []byte(secret)) {
			t.Fatalf("stripped SARIF still contains %q: %s", secret, stripped)
		}
	}
	if !bytes.Contains(stripped, []byte("kept: not a region")) {
		t.Fatal("a property that is not a region snippet was removed")
	}
	if !bytes.Contains(stripped, []byte("12345678901234567890")) {
		t.Fatal("large integer lost precision")
	}

	doc, err := Parse(bytes.NewReader(stripped))
	if err != nil {
		t.Fatalf("stripped document no longer parses: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("results lost: %+v", doc.Runs)
	}
	var check map[string]any
	if err := json.Unmarshal(stripped, &check); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

// The output is always re-encoded, never the input bytes: a document with
// nothing to strip comes back compacted, numbers and strings intact.
func TestStripSnippetsAlwaysReencodes(t *testing.T) {
	content := []byte("{ \"version\" : \"2.1.0\",\n \"runs\": [], \"n\": 1.50e3, \"s\": \"<a & b>\\u00e9\" }")
	stripped, err := StripSnippets(content)
	if err != nil {
		t.Fatalf("StripSnippets: %v", err)
	}
	if want := `{"version":"2.1.0","runs":[],"n":1.50e3,"s":"<a & b>é"}`; string(stripped) != want {
		t.Fatalf("StripSnippets = %s, want %s", stripped, want)
	}
}

// Duplicate keys: a map decode keeps only the last "region", so a sanitizer
// that compared decoded trees could see "nothing to strip" and return the
// original bytes — snippet included. Every occurrence must be filtered.
func TestStripSnippetsFiltersDuplicateKeys(t *testing.T) {
	content := []byte(`{"runs":[{"results":[{"locations":[{"physicalLocation":{
		"region":{"startLine":1,"snippet":{"text":"DUP-SECRET-1"}},
		"region":{"startLine":1},
		"contextRegion":{"snippet":{"text":"DUP-SECRET-2"},"snippet":{"text":"DUP-SECRET-3"}}}}]}]}]}`)
	stripped, err := StripSnippets(content)
	if err != nil {
		t.Fatalf("StripSnippets: %v", err)
	}
	if bytes.Contains(stripped, []byte("DUP-SECRET")) {
		t.Fatalf("duplicate-key snippet survived: %s", stripped)
	}
}

// File contents ride in artifacts[].contents, fix replacements and rendered
// artifactContent too.
func TestStripSnippetsRemovesArtifactContents(t *testing.T) {
	content := []byte(`{"version":"2.1.0","runs":[{
		"artifacts":[{"location":{"uri":"app.env"},"length":12,"contents":{"text":"KEY=FILE-SECRET","binary":"QklOLVNFQ1JFVA==","rendered":{"text":"R"}}}],
		"results":[{"ruleId":"r","message":{"text":"m"},
			"fixes":[{"description":{"text":"keep me"},"artifactChanges":[{"artifactLocation":{"uri":"app.env"},
				"replacements":[{"deletedRegion":{"startLine":3},"insertedContent":{"text":"FIX-INSERTED-SECRET"}}]}]}],
			"properties":{"contents":"kept: not an artifact","x":{"rendered":{"markdown":"RENDERED-SECRET"}},"rendered":"kept: not an object"}
		}]}]}`)
	stripped, err := StripSnippets(content)
	if err != nil {
		t.Fatalf("StripSnippets: %v", err)
	}
	for _, secret := range []string{"FILE-SECRET", "QklOLVNFQ1JFVA", "FIX-INSERTED-SECRET", "RENDERED-SECRET"} {
		if bytes.Contains(stripped, []byte(secret)) {
			t.Fatalf("stripped SARIF still contains %q: %s", secret, stripped)
		}
	}
	for _, kept := range []string{"keep me", "kept: not an artifact", "kept: not an object", `"length":12`, `"startLine":3`} {
		if !bytes.Contains(stripped, []byte(kept)) {
			t.Fatalf("stripped SARIF lost %q: %s", kept, stripped)
		}
	}
	if _, err := Parse(bytes.NewReader(stripped)); err != nil {
		t.Fatalf("stripped document no longer parses: %v", err)
	}
}

func TestStripSnippetsRejectsTrailingDataAndOversize(t *testing.T) {
	for _, content := range []string{
		`{"runs":[]} {"runs":[{"results":[{"region":{"snippet":"S"}}]}]}`,
		`{"runs":[]}]`,
		`{"runs":[]} trailing`,
	} {
		if _, err := StripSnippets([]byte(content)); err == nil {
			t.Fatalf("StripSnippets(%q) accepted trailing data", content)
		}
	}
	if _, err := StripSnippets([]byte(`{"runs":[]}` + "\n\t ")); err != nil {
		t.Fatalf("trailing whitespace refused: %v", err)
	}
	big := make([]byte, MaxDocumentSize+1)
	if _, err := StripSnippets(big); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("oversize err = %v, want ErrDocumentTooLarge", err)
	}
	deep := bytes.Repeat([]byte(`{"a":`), maxSanitizeDepth+1)
	deep = append(append(deep, '1'), bytes.Repeat([]byte("}"), maxSanitizeDepth+1)...)
	if _, err := StripSnippets(deep); err == nil {
		t.Fatal("over-deep document accepted")
	}
}

func TestStripSnippetsRejectsNonObjects(t *testing.T) {
	for _, content := range []string{`[]`, `not json`, ``, `{"a":`, `{"a" 1}`} {
		if _, err := StripSnippets([]byte(content)); err == nil {
			t.Fatalf("StripSnippets(%q) error = nil", content)
		}
	}
}
