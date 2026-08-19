package delta

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	storepkg "github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type licenseTestStore struct {
	*mockStore
	components map[uuid.UUID][]dbgen.Component
}

func (m *licenseTestStore) ListComponentsBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error) {
	return m.components[snapshotID], nil
}

func TestEvaluateGatesWithConfigVulnerabilityThresholds(t *testing.T) {
	mock := newMockStore()
	service := NewService(mock, zerolog.Nop())
	maxHigh := 0
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{Type: "dependency", Severity: storepkg.SeverityLevelHigh},
		{Type: "sast", Severity: storepkg.SeverityLevelHigh}, // weakness gates own SAST
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, &GateConfig{
		Vulnerabilities: &VulnerabilityGate{MaxHigh: &maxHigh},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed || !gate.Configured {
		t.Fatalf("gate = %+v, want failed+configured", gate)
	}
	if len(gate.Reasons) != 1 {
		t.Fatalf("reasons = %v, want exactly the dependency-high reason", gate.Reasons)
	}
}

func TestEvaluateGatesWithConfigSecretsThreshold(t *testing.T) {
	mock := newMockStore()
	service := NewService(mock, zerolog.Nop())
	maxNew := 0
	filePath := "config/prod.env"
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{Type: "secret", Severity: storepkg.SeverityLevelCritical, FilePath: &filePath},
		{Type: "dependency", Severity: storepkg.SeverityLevelHigh}, // not a secret, must not count
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, &GateConfig{
		Secrets: &SecretsGate{MaxNew: &maxNew},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed || !gate.Configured {
		t.Fatalf("gate = %+v, want failed+configured", gate)
	}
	if len(gate.Reasons) != 1 {
		t.Fatalf("reasons = %v, want exactly the secret reason", gate.Reasons)
	}
	// The reason must locate the leak, never reveal it.
	if want := "1 new secret findings exceed the maximum 0 (in config/prod.env)"; gate.Reasons[0] != want {
		t.Fatalf("reason = %q, want %q", gate.Reasons[0], want)
	}
}

func TestEvaluateGatesWithConfigSecretsUnderThresholdPasses(t *testing.T) {
	mock := newMockStore()
	service := NewService(mock, zerolog.Nop())
	maxNew := 1
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{Type: "secret", Severity: storepkg.SeverityLevelCritical},
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, &GateConfig{
		Secrets: &SecretsGate{MaxNew: &maxNew},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed || !gate.Configured {
		t.Fatalf("gate = %+v, want passed+configured", gate)
	}
}

func TestEvaluateGatesWithConfigLicensePolicy(t *testing.T) {
	base := newMockStore()
	snapshotID := uuid.New()
	mock := &licenseTestStore{mockStore: base, components: map[uuid.UUID][]dbgen.Component{
		snapshotID: {
			{Name: "readline", Version: "8.2", Licenses: []string{"GPL-3.0-only"}},
			{Name: "lodash", Version: "4.17.21", Licenses: []string{"MIT"}},
			{Name: "mystery", Version: "1.0", Licenses: []string{}},
		},
	}}
	service := NewService(mock, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}, DenyUnknown: true},
		HeadSnapshotID: snapshotID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatalf("gate should fail, reasons=%v", gate.Reasons)
	}
	if len(gate.Reasons) != 2 {
		t.Fatalf("want copyleft + unknown reasons, got %v", gate.Reasons)
	}
}

// Malware is unconditionally blocking: the block runs on every gate
// evaluation, independent of which gate sections are configured, and the
// reason names the package.
func TestMalwareBlockIsUnconditional(t *testing.T) {
	name := "evil-pkg"
	version := "1.0.0"
	newVulns := []storepkg.Vulnerability{
		{Type: "malware", Severity: storepkg.SeverityLevelCritical, ComponentName: &name, ComponentVersion: &version},
		{Type: "sast", Severity: storepkg.SeverityLevelCritical},
	}

	reasons := evaluateMalwareBlock(newVulns)
	if len(reasons) != 1 {
		t.Fatalf("want exactly the malware reason, got %v", reasons)
	}
	if want := "1 malicious packages introduced: evil-pkg@1.0.0"; reasons[0] != want {
		t.Fatalf("reason = %q, want %q", reasons[0], want)
	}
	if reasons := evaluateMalwareBlock(newVulns[1:]); len(reasons) != 0 {
		t.Fatalf("non-malware findings must not trip the block, got %v", reasons)
	}

	// Malware also counts toward the vulnerabilities-section thresholds when
	// that section exists.
	zero := 0
	reasons = evaluateNewVulnerabilityGate(newVulns, &VulnerabilityGate{MaxCritical: &zero})
	if len(reasons) != 1 {
		t.Fatalf("want the critical-threshold reason, got %v", reasons)
	}

	// End to end through EvaluateGatesWithConfig with NO gate sections
	// configured at all: the malware block must still fire.
	service := NewService(newMockStore(), zerolog.Nop())
	result, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{New: newVulns}, nil)
	if err != nil {
		t.Fatalf("EvaluateGatesWithConfig: %v", err)
	}
	if result.Passed || len(result.Reasons) != 1 {
		t.Fatalf("gate with no configured sections must fail on malware, got passed=%v reasons=%v", result.Passed, result.Reasons)
	}
}
