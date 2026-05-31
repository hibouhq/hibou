package delta

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	storepkg "github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type mockStore struct {
	vulnsBySnapshot map[uuid.UUID][]storepkg.Vulnerability
	repoGates       map[uuid.UUID][]dbgen.QualityGate
	orgGates        map[uuid.UUID][]dbgen.QualityGate
	vexByKey        map[string]dbgen.VexStatement
	snapshots       map[uuid.UUID]*storepkg.Snapshot
	refs            map[uuid.UUID]*storepkg.Ref
	repos           map[uuid.UUID]*storepkg.Repository
	components      map[uuid.UUID]dbgen.Component
}

func newMockStore() *mockStore {
	return &mockStore{
		vulnsBySnapshot: map[uuid.UUID][]storepkg.Vulnerability{},
		repoGates:       map[uuid.UUID][]dbgen.QualityGate{},
		orgGates:        map[uuid.UUID][]dbgen.QualityGate{},
		vexByKey:        map[string]dbgen.VexStatement{},
		snapshots:       map[uuid.UUID]*storepkg.Snapshot{},
		refs:            map[uuid.UUID]*storepkg.Ref{},
		repos:           map[uuid.UUID]*storepkg.Repository{},
		components:      map[uuid.UUID]dbgen.Component{},
	}
}

func (m *mockStore) ListAllVulnerabilitiesBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]storepkg.Vulnerability, error) {
	return append([]storepkg.Vulnerability(nil), m.vulnsBySnapshot[snapshotID]...), nil
}

func (m *mockStore) ListQualityGatesByRepo(_ context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error) {
	return append([]dbgen.QualityGate(nil), m.repoGates[repoID]...), nil
}

func (m *mockStore) ListOrgWideQualityGates(_ context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return append([]dbgen.QualityGate(nil), m.orgGates[orgID]...), nil
}

func (m *mockStore) GetEffectiveVEXStatus(_ context.Context, arg dbgen.GetEffectiveVEXStatusParams) (dbgen.VexStatement, error) {
	if statement, ok := m.vexByKey[m.vexLookupKey(arg)]; ok {
		return statement, nil
	}
	return dbgen.VexStatement{}, sql.ErrNoRows
}

func (m *mockStore) GetSnapshotByID(_ context.Context, id uuid.UUID) (*storepkg.Snapshot, error) {
	return m.snapshots[id], nil
}

func (m *mockStore) GetRefByID(_ context.Context, id uuid.UUID) (*storepkg.Ref, error) {
	return m.refs[id], nil
}

func (m *mockStore) GetRepositoryByID(_ context.Context, id uuid.UUID) (*storepkg.Repository, error) {
	return m.repos[id], nil
}

func (m *mockStore) GetComponentByID(_ context.Context, id uuid.UUID) (dbgen.Component, error) {
	component, ok := m.components[id]
	if !ok {
		return dbgen.Component{}, sql.ErrNoRows
	}
	return component, nil
}

func (m *mockStore) vexLookupKey(arg dbgen.GetEffectiveVEXStatusParams) string {
	component := ""
	if arg.ComponentPurl.Valid {
		component = arg.ComponentPurl.String
	}
	repoID := ""
	if arg.RepoID.Valid {
		repoID = arg.RepoID.UUID.String()
	}
	return arg.OrgID.String() + ":" + arg.AdvisoryID.String() + ":" + repoID + ":" + component
}

func TestComputeDeltaEmptySnapshots(t *testing.T) {
	service := NewService(newMockStore(), zerolog.Nop())
	result, err := service.ComputeDelta(context.Background(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 0 || len(result.Resolved) != 0 {
		t.Fatalf("expected empty delta, got %#v", result)
	}
	if result.Unchanged != 0 {
		t.Fatalf("expected zero unchanged count, got %#v", result)
	}
}

func TestComputeDeltaDetectsNewAndResolvedVulns(t *testing.T) {
	mock := newMockStore()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	mock.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-0001", Severity: storepkg.SeverityLevelCritical, Fingerprint: "fp-new"}}
	mock.vulnsBySnapshot[targetSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-0002", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-old"}}
	service := NewService(mock, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 1 || result.New[0].Title != "CVE-2026-0001" {
		t.Fatalf("expected one new vulnerability, got %#v", result.New)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].Title != "CVE-2026-0002" {
		t.Fatalf("expected one resolved vulnerability, got %#v", result.Resolved)
	}
}

func TestComputeDeltaDetectsFindingChanges(t *testing.T) {
	mock := newMockStore()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	mock.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "sast", Title: "new", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-new"}}
	mock.vulnsBySnapshot[targetSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "sast", Title: "old", Severity: storepkg.SeverityLevelLow, Fingerprint: "fp-old"}}
	service := NewService(mock, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 1 || result.New[0].Fingerprint != "fp-new" {
		t.Fatalf("expected one new vulnerability, got %#v", result.New)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].Fingerprint != "fp-old" {
		t.Fatalf("expected one resolved vulnerability, got %#v", result.Resolved)
	}
}

func TestComputeDeltaKeepsAdvisoryWhenOnlyOneComponentIsVEXed(t *testing.T) {
	mock := newMockStore()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	refID := uuid.New()
	repoID := uuid.New()
	orgID := uuid.New()
	advisoryID := uuid.New()
	componentAID := uuid.New()
	componentBID := uuid.New()
	mock.snapshots[prSnapshotID] = &storepkg.Snapshot{ID: prSnapshotID, RefID: refID}
	mock.refs[refID] = &storepkg.Ref{ID: refID, RepoID: repoID}
	mock.repos[repoID] = &storepkg.Repository{ID: repoID, OrgID: orgID}
	mock.components[componentAID] = dbgen.Component{ID: componentAID, Purl: "pkg:golang/example/a@1.0.0"}
	mock.components[componentBID] = dbgen.Component{ID: componentBID, Purl: "pkg:golang/example/b@1.0.0"}
	mock.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{
		{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-1000", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-a", AdvisoryID: &advisoryID, ComponentID: &componentAID},
		{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-1000", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-b", AdvisoryID: &advisoryID, ComponentID: &componentBID},
	}
	mock.vexByKey[mock.vexLookupKey(dbgen.GetEffectiveVEXStatusParams{
		OrgID:         orgID,
		AdvisoryID:    advisoryID,
		RepoID:        uuid.NullUUID{UUID: repoID, Valid: true},
		ComponentPurl: sql.NullString{String: "pkg:golang/example/a@1.0.0", Valid: true},
	})] = dbgen.VexStatement{Status: dbgen.VexStatusNotAffected}

	service := NewService(mock, zerolog.Nop(), mock)
	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 1 || result.New[0].Title != "CVE-2026-1000" {
		t.Fatalf("expected vulnerability to remain because one component is still affected, got %#v", result.New)
	}
}

func TestEvaluateGatesPassAndFail(t *testing.T) {
	repoID := uuid.New()
	orgID := uuid.New()
	mock := newMockStore()
	mock.repoGates[repoID] = []dbgen.QualityGate{{
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
	service := NewService(mock, zerolog.Nop())

	pass, err := service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelHigh}}})
	if err != nil {
		t.Fatalf("EvaluateGates returned error: %v", err)
	}
	if !pass.Passed || len(pass.Reasons) != 0 {
		t.Fatalf("expected passing gate result, got %#v", pass)
	}

	fail, err := service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelCritical}, {Severity: storepkg.SeverityLevelHigh}, {Severity: storepkg.SeverityLevelCritical}}})
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
	mock := newMockStore()
	mock.orgGates[orgID] = []dbgen.QualityGate{{
		ID:          uuid.New(),
		OrgID:       orgID,
		Name:        "org gate",
		MaxCritical: 0,
		MaxHigh:     0,
		Enabled:     true,
	}}
	service := NewService(mock, zerolog.Nop())

	result, err := service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelHigh}}})
	if err != nil {
		t.Fatalf("EvaluateGates returned error: %v", err)
	}
	if result.Passed || len(result.Reasons) == 0 {
		t.Fatalf("expected org-wide gate fallback to fail, got %#v", result)
	}

	mock.repoGates[repoID] = []dbgen.QualityGate{{
		ID:          uuid.New(),
		OrgID:       orgID,
		RepoID:      uuid.NullUUID{UUID: repoID, Valid: true},
		Name:        "repo gate",
		MaxCritical: 1,
		MaxHigh:     1,
		Enabled:     true,
	}}

	result, err = service.EvaluateGates(context.Background(), repoID, orgID, &DeltaResult{New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelHigh}}})
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
	mock := newMockStore()
	mock.repoGates[repoID] = []dbgen.QualityGate{{
		ID:             uuid.New(),
		OrgID:          orgID,
		RepoID:         uuid.NullUUID{UUID: repoID, Valid: true},
		Name:           "repo gate",
		MaxCritical:    0,
		MaxHigh:        0,
		MaxNewFindings: sql.NullInt32{Int32: 0, Valid: true},
		Enabled:        true,
	}}
	service := NewService(mock, zerolog.Nop())
	weaknessGate := &WeaknessGate{MaxCritical: intPtr(1), MaxHigh: intPtr(1)}

	result, err := service.EvaluateGatesWithConfig(context.Background(), repoID, orgID, &DeltaResult{
		New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelMedium}},
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
	mock := newMockStore()
	mock.repoGates[repoID] = []dbgen.QualityGate{{
		ID:             uuid.New(),
		OrgID:          orgID,
		RepoID:         uuid.NullUUID{UUID: repoID, Valid: true},
		Name:           "repo gate",
		MaxCritical:    0,
		MaxHigh:        0,
		MaxNewFindings: sql.NullInt32{Int32: 0, Valid: true},
		Enabled:        true,
	}}
	service := NewService(mock, zerolog.Nop())
	disabled := false
	weaknessGate := &WeaknessGate{Enabled: &disabled}

	result, err := service.EvaluateGatesWithConfig(context.Background(), repoID, orgID, &DeltaResult{
		New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelMedium}},
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
	mock := newMockStore()
	mock.repoGates[repoID] = []dbgen.QualityGate{{
		ID:          uuid.New(),
		OrgID:       orgID,
		RepoID:      uuid.NullUUID{UUID: repoID, Valid: true},
		Name:        "repo gate",
		MaxCritical: 0,
		MaxHigh:     0,
		Enabled:     true,
	}}
	service := NewService(mock, zerolog.Nop())
	weaknessGate := &WeaknessGate{MaxCritical: intPtr(10)}

	result, err := service.EvaluateGatesWithConfig(context.Background(), repoID, orgID, &DeltaResult{
		New: []storepkg.Vulnerability{{Severity: storepkg.SeverityLevelCritical}},
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
