package sarif

import (
	"bytes"
	"encoding/json"
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

func TestStripSnippetsLeavesSnippetFreeDocumentUntouched(t *testing.T) {
	content := []byte(`{"version":"2.1.0","runs":[]}`)
	stripped, err := StripSnippets(content)
	if err != nil || !bytes.Equal(stripped, content) {
		t.Fatalf("StripSnippets = %s, %v; want the input unchanged", stripped, err)
	}
}

func TestStripSnippetsRejectsNonObjects(t *testing.T) {
	for _, content := range []string{`[]`, `not json`, ``} {
		if _, err := StripSnippets([]byte(content)); err == nil {
			t.Fatalf("StripSnippets(%q) error = nil", content)
		}
	}
}
