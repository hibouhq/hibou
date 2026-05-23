package sarif

import (
	"strings"
	"testing"
)

func TestParseAndExtractFindings(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"semgrep","rules":[{"id":"rule-1","name":"Hardcoded secret","helpUri":"https://example.com/rule-1","properties":{"tags":["security","CWE-798"]}}]}},
			"results":[{
				"ruleId":"rule-1",
				"level":"warning",
				"message":{"text":"Potential secret"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/main.go"},"region":{"startLine":12,"endLine":12}}}]
			}]
		}]
	}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	findings, err := ExtractFindings(doc, "repo-123")
	if err != nil {
		t.Fatalf("ExtractFindings returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Tool != "semgrep" {
		t.Fatalf("expected semgrep tool, got %q", finding.Tool)
	}
	if finding.Severity != "medium" {
		t.Fatalf("expected medium severity, got %q", finding.Severity)
	}
	if finding.FilePath != "app/main.go" || finding.StartLine != 12 || finding.EndLine != 12 {
		t.Fatalf("unexpected location: %#v", finding)
	}
	if cwes, ok := finding.Metadata["cwes"].([]string); !ok || len(cwes) != 1 || cwes[0] != "CWE-798" {
		t.Fatalf("expected CWE metadata, got %#v", finding.Metadata["cwes"])
	}
}

func TestMapSeverity(t *testing.T) {
	tests := map[string]string{
		"error":   "high",
		"warning": "medium",
		"note":    "low",
		"none":    "info",
		"other":   "info",
	}

	for input, want := range tests {
		if got := mapSeverity(input); got != want {
			t.Fatalf("mapSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFingerprintStability(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"codeql","rules":[{"id":"go/sql-injection","properties":{"tags":[]}}]}},
			"results":[{
				"ruleId":"go/sql-injection",
				"level":"error",
				"message":{"text":"SQL injection"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"server/query.go"},"region":{"startLine":44,"endLine":46}}}]
			}]
		}]
	}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	left, err := ExtractFindings(doc, "repo-A")
	if err != nil {
		t.Fatalf("ExtractFindings left returned error: %v", err)
	}
	right, err := ExtractFindings(doc, "repo-A")
	if err != nil {
		t.Fatalf("ExtractFindings right returned error: %v", err)
	}
	if left[0].Fingerprint != right[0].Fingerprint || left[0].LocationHash != right[0].LocationHash {
		t.Fatalf("expected stable hashes, got %q/%q and %q/%q", left[0].Fingerprint, left[0].LocationHash, right[0].Fingerprint, right[0].LocationHash)
	}
}

func TestExtractFindingsPrefersProducerFingerprints(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"codeql","rules":[{"id":"go/sql-injection","properties":{"tags":[]}}]}},
			"results":[{
				"ruleId":"go/sql-injection",
				"level":"error",
				"message":{"text":"SQL injection"},
				"fingerprints":{"primaryLocationLineHash":"producer-stable"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"server/query.go"},"region":{"startLine":44,"endLine":46}}}]
			}]
		}]
	}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	findings, err := ExtractFindings(doc, "repo-A")
	if err != nil {
		t.Fatalf("ExtractFindings returned error: %v", err)
	}
	if findings[0].Fingerprint != "producer-stable" {
		t.Fatalf("expected producer fingerprint, got %q", findings[0].Fingerprint)
	}
}

func TestExtractFindingsFallsBackToPartialFingerprints(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"semgrep","rules":[{"id":"rule-1","properties":{"tags":[]}}]}},
			"results":[{
				"ruleId":"rule-1",
				"level":"warning",
				"message":{"text":"Potential secret"},
				"partialFingerprints":{"primaryLocationLineHash":"partial-stable"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/main.go"},"region":{"startLine":12,"endLine":12}}}]
			}]
		}]
	}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	findings, err := ExtractFindings(doc, "repo-123")
	if err != nil {
		t.Fatalf("ExtractFindings returned error: %v", err)
	}
	if findings[0].Fingerprint != "partial-stable" {
		t.Fatalf("expected partial fingerprint fallback, got %q", findings[0].Fingerprint)
	}
}

func TestExtractCWEsFromTags(t *testing.T) {
	cwes := extractCWEs([]string{"security", "cwe-79", "x:CWE-89", "cwe-79"})
	if len(cwes) != 2 || cwes[0] != "CWE-79" || cwes[1] != "CWE-89" {
		t.Fatalf("unexpected CWEs: %#v", cwes)
	}
}
