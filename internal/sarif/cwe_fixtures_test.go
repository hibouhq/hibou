package sarif

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Real scanner outputs (trimmed, paths scrubbed) for each CWE convention
// observed in ADR-037's survey. Expectations are read off the raw SARIF, not
// off the parser: a regression in either taxonomy or tag handling breaks one.
func TestExtractCWEsFromScannerFixtures(t *testing.T) {
	cases := map[string]map[string][]int{
		// Taxonomy, kinds superset, inline taxonomy.
		"gosec.sarif":    {"G404": {338}, "G101": {798}, "G501": {327}},
		"spotbugs.sarif": {"CIPHER_INTEGRITY": {353}, "COMMAND_INJECTION": {78}, "DES_USAGE": {327}},
		"zap.sarif":      {"10020": {1021}, "10038": {693}, "90003": {345}},
		// Taxonomy without kinds (= relevant), next to a custom Categories
		// taxonomy whose targets must not leak in.
		"kics.sarif": {
			"fd54f200-402c-4333-a5a4-36ef6709af2f": {250},
			"965a08d7-ef86-4f14-8792-4a3b2098937e": {1357},
			"d3499f6d-1651-41bb-a9a7-de925fea487b": {1357},
		},
		// Prefixed target ids, external taxonomy; the incomparable CWE-119 is
		// not a rule-level classification.
		"flawfinder.sarif": {"FF1013": {120}, "FF1001": {120}, "FF1015": {120}},
		// Zero-padded GitHub tags, several CWEs per rule.
		"codeql.sarif": {
			"js/missing-rate-limiting":                   {770, 307, 400},
			"js/regex-injection":                         {730, 400},
			"js/server-side-unvalidated-url-redirection": {601},
		},
		// Titled tags.
		"semgrep.sarif": {
			"python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args": {78},
			"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true":                                         {78},
		},
		"bandit.sarif": {"B404": {78}, "B602": {78}, "B607": {78}},
		// No CWE anywhere in Brakeman's SARIF.
		"brakeman.sarif": {"BRAKE0120": nil, "BRAKE0013": nil, "BRAKE0014": nil},
	}
	for file, want := range cases {
		t.Run(file, func(t *testing.T) {
			got := ruleCWEsByID(t, file)
			for ruleID, cwes := range want {
				actual, ok := got[ruleID]
				if !ok {
					t.Errorf("rule %s: no finding extracted", ruleID)
					continue
				}
				if !slices.Equal(actual, cwes) && (len(actual) != 0 || len(cwes) != 0) {
					t.Errorf("rule %s: CWEs = %v, want %v", ruleID, actual, cwes)
				}
			}
		})
	}
}

// Spec paths no surveyed tool exercises: rules defined in tool.extensions
// (§3.54.2), guid-only taxonomy references resolved by taxon index or guid,
// relationship kinds that do not classify, and per-result taxa (§3.27.8).
func TestExtractCWEsSyntheticTaxonomyPaths(t *testing.T) {
	findings := extractFixture(t, "synthetic-taxonomy.sarif")
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	ext := findings[0]
	if ext.RuleID != "EXT1" || ext.Rule == nil || !slices.Equal(ext.Rule.CWEs, []int{22}) {
		t.Fatalf("extension rule: id %q, rule %+v", ext.RuleID, ext.Rule)
	}
	drv := findings[1]
	// equal counts; disjoint, canPrecede and subset do not.
	if drv.Rule == nil || !slices.Equal(drv.Rule.CWEs, []int{89}) {
		t.Fatalf("driver rule CWEs = %+v", drv.Rule)
	}
	// result.taxa: by id, and by guid into the inline taxonomy; the Custom
	// taxonomy's "79" is not a CWE.
	if !slices.Equal(drv.ResultCWEs, []int{707, 200}) {
		t.Fatalf("result CWEs = %v, want [707 200]", drv.ResultCWEs)
	}
}

func extractFixture(t *testing.T, file string) []Finding {
	t.Helper()
	handle, err := os.Open(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	doc, err := Parse(handle)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	findings, err := ExtractFindings(doc, "repo")
	if err != nil {
		t.Fatalf("extract %s: %v", file, err)
	}
	return findings
}

func ruleCWEsByID(t *testing.T, file string) map[string][]int {
	t.Helper()
	out := map[string][]int{}
	for _, finding := range extractFixture(t, file) {
		var cwes []int
		if finding.Rule != nil {
			cwes = finding.Rule.CWEs
		}
		out[finding.RuleID] = cwes
	}
	return out
}
