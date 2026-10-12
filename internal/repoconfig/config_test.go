package repoconfig

import (
	"strings"
	"testing"
)

func TestParseValidConfig(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["main", "release/*"]
    code:
      max_critical: 0
      max_high: 1
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Version != 1 || len(cfg.QualityGates) != 1 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if cfg.QualityGates[0].Code == nil || cfg.QualityGates[0].Code.EnabledValue() != true {
		t.Fatalf("expected enabled code thresholds, got %#v", cfg.QualityGates[0].Code)
	}
}

func TestParseConfigWithSecretsThreshold(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["main"]
    secrets:
      max_new: 0
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	secrets := cfg.QualityGates[0].Secrets
	if secrets == nil || secrets.MaxNew == nil || *secrets.MaxNew != 0 {
		t.Fatalf("expected secrets max_new 0, got %#v", secrets)
	}
}

func TestParseRejectsNegativeSecretsThreshold(t *testing.T) {
	_, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["main"]
    secrets:
      max_new: -1
`))
	if err == nil {
		t.Fatal("expected negative secrets.max_new to be rejected")
	}
}

func TestParseMinimalConfig(t *testing.T) {
	cfg, err := Parse([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(cfg.QualityGates) != 0 {
		t.Fatalf("expected no gates, got %#v", cfg.QualityGates)
	}
}

func TestParseConfigWithEnabledFalse(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["experiment/*"]
    code:
      enabled: false
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.QualityGates[0].Code == nil || cfg.QualityGates[0].Code.EnabledValue() {
		t.Fatalf("expected code gate to be disabled, got %#v", cfg.QualityGates[0].Code)
	}
}

func TestParseConfigWithCoverageThresholds(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["main"]
    coverage:
      min_coverage: 60
      grace: 2
      diff_minimum: 80
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.QualityGates[0].Coverage == nil {
		t.Fatal("expected coverage thresholds to be parsed")
	}
	if got := *cfg.QualityGates[0].Coverage.MinCoverage; got != 60 {
		t.Fatalf("expected min_coverage 60, got %v", got)
	}
	if got := *cfg.QualityGates[0].Coverage.Grace; got != 2 {
		t.Fatalf("expected grace 2, got %v", got)
	}
	if got := *cfg.QualityGates[0].Coverage.DiffMinimum; got != 80 {
		t.Fatalf("expected diff_minimum 80, got %v", got)
	}
}

func TestParseConfigWithCoverageExcludeAndUploadWindow(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
coverage:
  exclude:
    - "*_test.go"
    - "testutil/**"
upload:
  window: 10m
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Coverage == nil || len(cfg.Coverage.Exclude) != 2 {
		t.Fatalf("expected coverage exclude patterns, got %#v", cfg.Coverage)
	}
	if cfg.Upload == nil || cfg.Upload.Window != "10m" {
		t.Fatalf("expected upload window 10m, got %#v", cfg.Upload)
	}
}

func TestParseRejectsInvalidVersion(t *testing.T) {
	for _, raw := range []string{"version: 0\n", "version: 2\n"} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("expected Parse to reject %q", raw)
		}
	}
}

func TestParseRejectsEmptyBranches(t *testing.T) {
	_, err := Parse([]byte(`version: 1
quality_gates:
  - branches: []
`))
	if err == nil {
		t.Fatal("expected Parse to reject empty branches")
	}
}

func TestParseRejectsCoverageOutOfRange(t *testing.T) {
	for name, raw := range map[string]string{
		"negative": `version: 1
quality_gates:
  - branches: ["main"]
    coverage:
      grace: -1
`,
		"above 100": `version: 1
quality_gates:
  - branches: ["main"]
    coverage:
      min_coverage: 101
`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(raw))
			if err == nil {
				t.Fatal("expected Parse to reject out-of-range coverage threshold")
			}
			if !strings.Contains(err.Error(), "coverage") {
				t.Fatalf("expected coverage validation error, got %v", err)
			}
		})
	}
}

func TestParseRejectsInvalidUploadWindow(t *testing.T) {
	_, err := Parse([]byte(`version: 1
upload:
  window: someday
`))
	if err == nil {
		t.Fatal("expected Parse to reject invalid upload window")
	}
	if !strings.Contains(err.Error(), "upload.window") {
		t.Fatalf("expected upload.window error, got %v", err)
	}
}

func TestParseRejectsNegativeUploadWindow(t *testing.T) {
	_, err := Parse([]byte(`version: 1
upload:
  window: "-1m"
`))
	if err == nil {
		t.Fatal("expected Parse to reject negative upload window")
	}
	if !strings.Contains(err.Error(), "positive duration") {
		t.Fatalf("expected positive duration error, got %v", err)
	}
}

func TestDefaultProducesValidConfig(t *testing.T) {
	if _, err := Parse(DefaultYAML()); err != nil {
		t.Fatalf("DefaultYAML produced invalid config: %v", err)
	}
	if gate := Default().MatchGate("main"); gate == nil || gate.Code == nil {
		t.Fatalf("expected default config to match main gate")
	}
}

func TestMatchGateExactMatch(t *testing.T) {
	cfg := &RepoConfig{Version: 1, QualityGates: []QualityGate{{Branches: []string{"main"}}, {Branches: []string{"release/*"}}}}
	gate := cfg.MatchGate("main")
	if gate == nil || gate.Branches[0] != "main" {
		t.Fatalf("expected exact match gate, got %#v", gate)
	}
}

func TestMatchGateGlobMatch(t *testing.T) {
	cfg := &RepoConfig{Version: 1, QualityGates: []QualityGate{{Branches: []string{"release/*"}}}}
	gate := cfg.MatchGate("release/1.2")
	if gate == nil || gate.Branches[0] != "release/*" {
		t.Fatalf("expected glob match gate, got %#v", gate)
	}
}

func TestMatchGateMostSpecificWins(t *testing.T) {
	cfg := &RepoConfig{Version: 1, QualityGates: []QualityGate{{Branches: []string{"feature/*"}}, {Branches: []string{"feature/payments/*"}}}}
	gate := cfg.MatchGate("feature/payments/refactor")
	if gate == nil || gate.Branches[0] != "feature/payments/*" {
		t.Fatalf("expected most specific gate, got %#v", gate)
	}
}

func TestMatchGateNoMatchReturnsNil(t *testing.T) {
	cfg := &RepoConfig{Version: 1, QualityGates: []QualityGate{{Branches: []string{"main"}}}}
	if gate := cfg.MatchGate("develop"); gate != nil {
		t.Fatalf("expected no match, got %#v", gate)
	}
}

func TestParseReleasesTagPattern(t *testing.T) {
	cfg, err := Parse([]byte("version: 1\nreleases:\n  tag_pattern: \"^payments-v\\\\d+\\\\.\\\\d+$\"\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	pattern := cfg.Releases.CompiledTagPattern()
	if pattern == nil {
		t.Fatal("expected a compiled tag pattern")
	}
	if !pattern.MatchString("payments-v7.5") {
		t.Error("configured pattern should match payments-v7.5")
	}
	if pattern.MatchString("v7.5.0") {
		t.Error("configured pattern replaces the default; v7.5.0 must not match")
	}
}

func TestParseRejectsInvalidReleasesTagPattern(t *testing.T) {
	if _, err := Parse([]byte("version: 1\nreleases:\n  tag_pattern: \"([\"\n")); err == nil {
		t.Fatal("expected an error for an invalid tag_pattern regex")
	}
}

func TestCompiledTagPatternNilReceiver(t *testing.T) {
	var releases *ReleasesConfig
	if releases.CompiledTagPattern() != nil {
		t.Error("nil ReleasesConfig must yield no pattern (platform default applies)")
	}
}

// ADR-037 §7: a CWE deny section parses into selectors, and anything that
// would make it silently inert is a config error.
func TestCWEPolicy(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["main"]
    cwe:
      deny: [CWE-89, "78"]
      deny_tree: [CWE-74]
      deny_sets: [top25]
      deny_categories: [injection]
      types: [sast, dependency]
      min_severity: medium
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rules, err := cfg.QualityGates[0].CWE.Selectors()
	if err != nil || len(rules) != 5 {
		t.Fatalf("Selectors = %d rules, %v", len(rules), err)
	}
	if rules[2].Path != "cwe.deny_tree CWE-74" || !rules[2].Selector.Matches([]int{89}) {
		t.Fatalf("tree rule = %+v", rules[2])
	}

	for name, section := range map[string]string{
		"unknown id":       "deny: [CWE-99999]",
		"malformed id":     "deny: [sqli]",
		"coverage test":    "deny: [none]",
		"unknown set":      "deny_sets: [top-26]",
		"unknown category": "deny_categories: [sorcery]",
		"unknown type":     "deny: [CWE-89]\n      types: [binary]",
		"unknown severity": "deny: [CWE-89]\n      min_severity: severe",
		"denies nothing":   "types: [sast]",
	} {
		_, err := Parse([]byte("version: 1\nquality_gates:\n  - branches: [\"main\"]\n    cwe:\n      " + section + "\n"))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWeaknessesKeyPointsAtRename(t *testing.T) {
	_, err := Parse([]byte("version: 1\nquality_gates:\n  - branches: [\"main\"]\n    weaknesses:\n      max_high: 0\n"))
	if err == nil || !strings.Contains(err.Error(), "renamed to code") {
		t.Fatalf("want a rename hint, got %v", err)
	}
}

func TestParseScanners(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
scanners:
  Semgrep:
    scope: changed-files
  eslint:
    scope: partial
    paths: ["./web/", "tools"]
  gosec:
    scope: FULL
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if run, ok := cfg.ScannerRunFor("semgrep"); !ok || run.Scope != ScannerScopeChangedFiles {
		t.Fatalf("semgrep = %+v, %v; want changed-files (keys are case-insensitive)", run, ok)
	}
	if run, _ := cfg.ScannerRunFor("ESLint"); run.Scope != ScannerScopePartial || len(run.Paths) != 2 || run.Paths[0] != "web" {
		t.Fatalf("eslint = %+v; want partial [web tools]", run)
	}
	if run, _ := cfg.ScannerRunFor("gosec"); run.Scope != ScannerScopeFull {
		t.Fatalf("gosec = %+v; want full", run)
	}
	if _, ok := cfg.ScannerRunFor("trivy"); ok {
		t.Fatal("unlisted tool must not be configured")
	}
}

func TestParseRejectsInvalidScanners(t *testing.T) {
	for name, body := range map[string]string{
		"unknown scope":         "scanners:\n  semgrep:\n    scope: diff\n",
		"missing scope":         "scanners:\n  semgrep:\n    paths: [web]\n",
		"paths with full":       "scanners:\n  semgrep:\n    scope: full\n    paths: [web]\n",
		"paths with changed":    "scanners:\n  semgrep:\n    scope: changed-files\n    paths: [web]\n",
		"duplicate after lower": "scanners:\n  semgrep:\n    scope: full\n  Semgrep:\n    scope: full\n",
		"empty path":            "scanners:\n  eslint:\n    scope: partial\n    paths: [\"./\"]\n",
		"unknown field":         "scanners:\n  semgrep:\n    scope: full\n    config_digest: x\n",
	} {
		if _, err := Parse([]byte("version: 1\n" + body)); err == nil {
			t.Errorf("%s: Parse accepted %q", name, body)
		}
	}
}
