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
