package delta

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type mockStore struct {
	vulnsBySnapshot    map[uuid.UUID][]dbgen.VulnMatch
	findingsBySnapshot map[uuid.UUID][]dbgen.Finding
	advisories         map[uuid.UUID]dbgen.Advisory
	repoGates          map[uuid.UUID][]dbgen.QualityGate
	orgGates           map[uuid.UUID][]dbgen.QualityGate
}

func newMockStore() *mockStore {
	return &mockStore{
		vulnsBySnapshot:    map[uuid.UUID][]dbgen.VulnMatch{},
		findingsBySnapshot: map[uuid.UUID][]dbgen.Finding{},
		advisories:         map[uuid.UUID]dbgen.Advisory{},
		repoGates:          map[uuid.UUID][]dbgen.QualityGate{},
		orgGates:           map[uuid.UUID][]dbgen.QualityGate{},
	}
}

func (m *mockStore) ListVulnMatchesBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]dbgen.VulnMatch, error) {
	return append([]dbgen.VulnMatch(nil), m.vulnsBySnapshot[snapshotID]...), nil
}

func (m *mockStore) ListFindingsBySnapshot(_ context.Context, arg dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error) {
	rows := append([]dbgen.Finding(nil), m.findingsBySnapshot[arg.SnapshotID]...)
	start := int(arg.Offset)
	if start >= len(rows) {
		return nil, nil
	}
	end := start + int(arg.Limit)
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], nil
}

func (m *mockStore) GetAdvisoryByID(_ context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	return m.advisories[id], nil
}

func (m *mockStore) ListQualityGatesByRepo(_ context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error) {
	return append([]dbgen.QualityGate(nil), m.repoGates[repoID]...), nil
}

func (m *mockStore) ListOrgWideQualityGates(_ context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return append([]dbgen.QualityGate(nil), m.orgGates[orgID]...), nil
}

func TestComputeDeltaEmptySnapshots(t *testing.T) {
	service := NewService(newMockStore(), zerolog.Nop())
	result, err := service.ComputeDelta(context.Background(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.NewVulns) != 0 || len(result.ResolvedVulns) != 0 || len(result.NewFindings) != 0 || len(result.ResolvedFindings) != 0 {
		t.Fatalf("expected empty delta, got %#v", result)
	}
	if result.UnchangedVulns != 0 || result.UnchangedFindings != 0 {
		t.Fatalf("expected zero unchanged counts, got %#v", result)
	}
}

func TestComputeDeltaDetectsNewAndResolvedVulns(t *testing.T) {
	store := newMockStore()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	newAdvisoryID := uuid.New()
	resolvedAdvisoryID := uuid.New()
	store.vulnsBySnapshot[prSnapshotID] = []dbgen.VulnMatch{{AdvisoryID: newAdvisoryID}}
	store.vulnsBySnapshot[targetSnapshotID] = []dbgen.VulnMatch{{AdvisoryID: resolvedAdvisoryID}}
	store.advisories[newAdvisoryID] = dbgen.Advisory{ID: newAdvisoryID, CanonicalID: "CVE-2026-0001", Severity: dbgen.SeverityLevelCritical}
	store.advisories[resolvedAdvisoryID] = dbgen.Advisory{ID: resolvedAdvisoryID, CanonicalID: "CVE-2026-0002", Severity: dbgen.SeverityLevelHigh}
	service := NewService(store, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.NewVulns) != 1 || result.NewVulns[0].CanonicalID != "CVE-2026-0001" {
		t.Fatalf("expected one new vuln, got %#v", result.NewVulns)
	}
	if len(result.ResolvedVulns) != 1 || result.ResolvedVulns[0].CanonicalID != "CVE-2026-0002" {
		t.Fatalf("expected one resolved vuln, got %#v", result.ResolvedVulns)
	}
}

func TestComputeDeltaDetectsFindingChanges(t *testing.T) {
	store := newMockStore()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	store.findingsBySnapshot[prSnapshotID] = []dbgen.Finding{{Fingerprint: sql.NullString{String: "fp-new", Valid: true}, Tool: "semgrep", RuleID: "R1", Severity: dbgen.SeverityLevelHigh, FilePath: "main.go", Message: "new"}}
	store.findingsBySnapshot[targetSnapshotID] = []dbgen.Finding{{Fingerprint: sql.NullString{String: "fp-old", Valid: true}, Tool: "semgrep", RuleID: "R2", Severity: dbgen.SeverityLevelLow, FilePath: "old.go", Message: "old"}}
	service := NewService(store, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.NewFindings) != 1 || result.NewFindings[0].Fingerprint != "fp-new" {
		t.Fatalf("expected one new finding, got %#v", result.NewFindings)
	}
	if len(result.ResolvedFindings) != 1 || result.ResolvedFindings[0].Fingerprint != "fp-old" {
		t.Fatalf("expected one resolved finding, got %#v", result.ResolvedFindings)
	}
}

func TestEvaluateGatesPassAndFail(t *testing.T) {
	repoID := uuid.New()
	orgID := uuid.New()
	store := newMockStore()
	store.repoGates[repoID] = []dbgen.QualityGate{{
		ID:                uuid.New(),
		OrgID:             orgID,
		RepoID:            uuid.NullUUID{UUID: repoID, Valid: true},
		Name:              "repo gate",
		MaxCritical:       0,
		MaxHigh:           1,
		MaxMedium:         sql.NullInt32{Int32: 1, Valid: true},
		MaxNewFindings:    sql.NullInt32{Int32: 1, Valid: true},
		Enabled:           true,
		FindingSeverities: []string{"high", "critical"},
	}}
	service := NewService(store, zerolog.Nop())

	pass, err := service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{NewVulns: []VulnDelta{{Severity: "high"}}, NewFindings: []FindingDelta{{Severity: "low"}}})
	if err != nil {
		t.Fatalf("EvaluateGates returned error: %v", err)
	}
	if !pass.Passed || len(pass.Reasons) != 0 {
		t.Fatalf("expected passing gate result, got %#v", pass)
	}

	fail, err := service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{NewVulns: []VulnDelta{{Severity: "critical"}}, NewFindings: []FindingDelta{{Severity: "high"}, {Severity: "critical"}}})
	if err != nil {
		t.Fatalf("EvaluateGates returned error: %v", err)
	}
	if fail.Passed || len(fail.Reasons) == 0 {
		t.Fatalf("expected failing gate result, got %#v", fail)
	}
}

func TestEvaluateGatesFallsBackToOrgWideGatesOnlyWhenRepoHasNone(t *testing.T) {
	repoID := uuid.New()
	orgID := uuid.New()
	store := newMockStore()
	store.orgGates[orgID] = []dbgen.QualityGate{{
		ID:          uuid.New(),
		OrgID:       orgID,
		Name:        "org gate",
		MaxCritical: 0,
		MaxHigh:     0,
		Enabled:     true,
	}}
	service := NewService(store, zerolog.Nop())

	result, err := service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{NewVulns: []VulnDelta{{Severity: "high"}}})
	if err != nil {
		t.Fatalf("EvaluateGates returned error: %v", err)
	}
	if result.Passed || len(result.Reasons) == 0 {
		t.Fatalf("expected org-wide gate fallback to fail, got %#v", result)
	}

	store.repoGates[repoID] = []dbgen.QualityGate{{
		ID:          uuid.New(),
		OrgID:       orgID,
		RepoID:      uuid.NullUUID{UUID: repoID, Valid: true},
		Name:        "repo gate",
		MaxCritical: 1,
		MaxHigh:     1,
		Enabled:     true,
	}}

	result, err = service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{NewVulns: []VulnDelta{{Severity: "high"}}})
	if err != nil {
		t.Fatalf("EvaluateGates returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected repo-specific gate to suppress org fallback, got %#v", result)
	}
}

func TestEvaluateGatesWithConfigOverridesDBWeaknessGates(t *testing.T) {
	repoID := uuid.New()
	orgID := uuid.New()
	store := newMockStore()
	store.repoGates[repoID] = []dbgen.QualityGate{{
		ID:             uuid.New(),
		OrgID:          orgID,
		RepoID:         uuid.NullUUID{UUID: repoID, Valid: true},
		Name:           "repo gate",
		MaxCritical:    0,
		MaxHigh:        0,
		MaxNewFindings: sql.NullInt32{Int32: 0, Valid: true},
		Enabled:        true,
	}}
	service := NewService(store, zerolog.Nop())
	weaknessGate := &WeaknessGate{MaxCritical: intPtr(1), MaxHigh: intPtr(1)}

	result, err := service.EvaluateGatesWithConfig(context.Background(), repoID, orgID, &DeltaResult{
		NewFindings: []FindingDelta{{Severity: "high"}},
	}, weaknessGate)
	if err != nil {
		t.Fatalf("EvaluateGatesWithConfig returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected repo config to override DB weakness gate, got %#v", result)
	}
}

func TestEvaluateGatesWithConfigCanDisableWeaknessGates(t *testing.T) {
	repoID := uuid.New()
	orgID := uuid.New()
	store := newMockStore()
	store.repoGates[repoID] = []dbgen.QualityGate{{
		ID:             uuid.New(),
		OrgID:          orgID,
		RepoID:         uuid.NullUUID{UUID: repoID, Valid: true},
		Name:           "repo gate",
		MaxCritical:    0,
		MaxHigh:        0,
		MaxNewFindings: sql.NullInt32{Int32: 0, Valid: true},
		Enabled:        true,
	}}
	service := NewService(store, zerolog.Nop())
	disabled := false
	weaknessGate := &WeaknessGate{Enabled: &disabled}

	result, err := service.EvaluateGatesWithConfig(context.Background(), repoID, orgID, &DeltaResult{
		NewFindings: []FindingDelta{{Severity: "critical"}},
	}, weaknessGate)
	if err != nil {
		t.Fatalf("EvaluateGatesWithConfig returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected disabled weakness gates to pass, got %#v", result)
	}
}

func TestEvaluateGatesWithConfigKeepsDBVulnerabilityGates(t *testing.T) {
	repoID := uuid.New()
	orgID := uuid.New()
	store := newMockStore()
	store.repoGates[repoID] = []dbgen.QualityGate{{
		ID:          uuid.New(),
		OrgID:       orgID,
		RepoID:      uuid.NullUUID{UUID: repoID, Valid: true},
		Name:        "repo gate",
		MaxCritical: 0,
		MaxHigh:     0,
		Enabled:     true,
	}}
	service := NewService(store, zerolog.Nop())
	weaknessGate := &WeaknessGate{MaxCritical: intPtr(10)}

	result, err := service.EvaluateGatesWithConfig(context.Background(), repoID, orgID, &DeltaResult{
		NewVulns: []VulnDelta{{Severity: "critical"}},
	}, weaknessGate)
	if err != nil {
		t.Fatalf("EvaluateGatesWithConfig returned error: %v", err)
	}
	if result.Passed {
		t.Fatalf("expected DB vulnerability gates to remain active, got %#v", result)
	}
}

func intPtr(value int) *int {
	return &value
}
