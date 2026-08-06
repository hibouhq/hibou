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
	if finding.Rule == nil {
		t.Fatalf("expected rule descriptor, got nil")
	}
	if finding.Rule.Name != "Hardcoded secret" || finding.Rule.HelpURI != "https://example.com/rule-1" {
		t.Fatalf("unexpected rule descriptor: %#v", finding.Rule)
	}
	if len(finding.Rule.CWEs) != 1 || finding.Rule.CWEs[0] != "CWE-798" {
		t.Fatalf("expected CWE-798 on rule, got %#v", finding.Rule.CWEs)
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

// ADR-023: results the scanner itself suppressed in-source (semgrep/ESLint/
// checkov ship them by default) must be marked, never surfaced as active.
// Empty array = active (SARIF semantics); a rejected suppression is void.
func TestExtractFindingsSuppressions(t *testing.T) {
	doc, err := Parse(strings.NewReader(`{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"eslint"}},
			"results":[
				{
					"ruleId":"no-eval",
					"level":"error",
					"message":{"text":"suppressed one"},
					"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":1}}}],
					"suppressions":[{"kind":"inSource","justification":"test fixture"}]
				},
				{
					"ruleId":"no-eval",
					"level":"error",
					"message":{"text":"active with empty array"},
					"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{"startLine":2}}}],
					"suppressions":[]
				},
				{
					"ruleId":"no-eval",
					"level":"error",
					"message":{"text":"rejected suppression stays active"},
					"locations":[{"physicalLocation":{"artifactLocation":{"uri":"c.js"},"region":{"startLine":3}}}],
					"suppressions":[{"kind":"inSource","status":"rejected","justification":"nope"}]
				},
				{
					"ruleId":"no-eval",
					"level":"error",
					"message":{"text":"no field at all"},
					"locations":[{"physicalLocation":{"artifactLocation":{"uri":"d.js"},"region":{"startLine":4}}}]
				}
			]
		}]
	}`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	findings, err := ExtractFindings(doc, "repo-123")
	if err != nil {
		t.Fatalf("ExtractFindings returned error: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	suppressed := findings[0]
	if !suppressed.Suppressed || suppressed.SuppressionKind != "inSource" || suppressed.SuppressionJustification != "test fixture" {
		t.Fatalf("suppressed finding not marked: %#v", suppressed)
	}
	for i, want := range []string{"active with empty array", "rejected suppression stays active", "no field at all"} {
		finding := findings[i+1]
		if finding.Suppressed {
			t.Fatalf("%q must stay active, got %#v", want, finding)
		}
	}
}
