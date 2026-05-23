package repoconfig

import "testing"

func TestParseValidConfig(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
quality_gates:
  - branches: ["main", "release/*"]
    weaknesses:
      max_critical: 0
      max_high: 1
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.Version != 1 || len(cfg.QualityGates) != 1 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if cfg.QualityGates[0].Weaknesses == nil || cfg.QualityGates[0].Weaknesses.EnabledValue() != true {
		t.Fatalf("expected enabled weakness thresholds, got %#v", cfg.QualityGates[0].Weaknesses)
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
    weaknesses:
      enabled: false
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.QualityGates[0].Weaknesses == nil || cfg.QualityGates[0].Weaknesses.EnabledValue() {
		t.Fatalf("expected weakness gate to be disabled, got %#v", cfg.QualityGates[0].Weaknesses)
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

func TestDefaultProducesValidConfig(t *testing.T) {
	if _, err := Parse(DefaultYAML()); err != nil {
		t.Fatalf("DefaultYAML produced invalid config: %v", err)
	}
	if gate := Default().MatchGate("main"); gate == nil || gate.Weaknesses == nil {
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
