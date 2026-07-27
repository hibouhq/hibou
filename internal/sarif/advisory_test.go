package sarif

import "testing"

func TestIsAdvisoryFinding(t *testing.T) {
	advisory := map[string]bool{
		"CVE-2022-3064":       true,
		"cve-2021-4235":       true,
		"GHSA-jfh8-c2jp-5v3q": true,
		"RUSTSEC-2020-0071":   true,
		"GO-2022-0603":        true,
		"PYSEC-2021-317":      true,
		"DSA-5122-1":          true,
		"USN-5260-1":          true,
		"G101":                false,
		"gosec-G204":          false,
		"typescript:S1135":    false,
		"CVE":                 false,
	}
	for ruleID, want := range advisory {
		if got := IsAdvisoryFinding(ruleID, nil); got != want {
			t.Errorf("IsAdvisoryFinding(%q, nil) = %v, want %v", ruleID, got, want)
		}
	}

	tagged := &RuleDescriptor{Tags: []string{"security", "Vulnerability"}}
	if !IsAdvisoryFinding("vendor-rule-1", tagged) {
		t.Error("vulnerability-tagged rule should be treated as an advisory")
	}
	sast := &RuleDescriptor{Tags: []string{"security", "sast"}}
	if IsAdvisoryFinding("vendor-rule-1", sast) {
		t.Error("plain security tag must not be treated as an advisory")
	}
}
