package scanner

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/advisory"
	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/provider"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type mockScannerStore struct {
	components       []dbgen.Component
	affectedRanges   map[string][]dbgen.AffectedRange
	scanStatuses     []dbgen.UpdateScanStatusParams
	providerStatuses map[string]dbgen.UpdateScanProviderParams
	vulnMatches      []dbgen.UpsertVulnMatchParams
	markStaleCalls   []dbgen.MarkStaleVulnMatchesParams
	upsertedMatchIDs []uuid.UUID
	auditLogs        []dbgen.CreateAuditLogParams
	createdScanID    uuid.UUID
	providerIDs      map[string]uuid.UUID
}

func newMockScannerStore() *mockScannerStore {
	return &mockScannerStore{
		affectedRanges:   map[string][]dbgen.AffectedRange{},
		providerStatuses: map[string]dbgen.UpdateScanProviderParams{},
		providerIDs:      map[string]uuid.UUID{},
	}
}

func (m *mockScannerStore) ListComponentsBySnapshot(context.Context, uuid.UUID) ([]dbgen.Component, error) {
	return append([]dbgen.Component(nil), m.components...), nil
}

func (m *mockScannerStore) CreateScan(_ context.Context, arg dbgen.CreateScanParams) (dbgen.Scan, error) {
	m.createdScanID = uuid.New()
	return dbgen.Scan{ID: m.createdScanID, SnapshotID: arg.SnapshotID, Status: arg.Status, ProvidersRequested: arg.ProvidersRequested, TriggeredBy: arg.TriggeredBy}, nil
}

func (m *mockScannerStore) UpdateScanStatus(_ context.Context, arg dbgen.UpdateScanStatusParams) (dbgen.Scan, error) {
	m.scanStatuses = append(m.scanStatuses, arg)
	return dbgen.Scan{ID: arg.ID, Status: arg.Status, ErrorMessage: arg.ErrorMessage, StartedAt: arg.StartedAt, CompletedAt: arg.CompletedAt}, nil
}

func (m *mockScannerStore) CreateScanProvider(_ context.Context, arg dbgen.CreateScanProviderParams) (dbgen.ScanProvider, error) {
	id := uuid.New()
	m.providerIDs[arg.Provider] = id
	return dbgen.ScanProvider{ID: id, ScanID: arg.ScanID, Provider: arg.Provider, Status: arg.Status}, nil
}

func (m *mockScannerStore) UpdateScanProvider(_ context.Context, arg dbgen.UpdateScanProviderParams) (dbgen.ScanProvider, error) {
	providerName := ""
	for name, id := range m.providerIDs {
		if id == arg.ID {
			providerName = name
			break
		}
	}
	m.providerStatuses[providerName] = arg
	return dbgen.ScanProvider{ID: arg.ID, Provider: providerName, Status: arg.Status}, nil
}

func (m *mockScannerStore) ListAffectedRangesByPackage(_ context.Context, arg dbgen.ListAffectedRangesByPackageParams) ([]dbgen.AffectedRange, error) {
	return append([]dbgen.AffectedRange(nil), m.affectedRanges[packageKey(arg.Ecosystem, arg.PackageName)]...), nil
}

func (m *mockScannerStore) UpsertVulnMatch(_ context.Context, arg dbgen.UpsertVulnMatchParams) (dbgen.VulnMatch, error) {
	m.vulnMatches = append(m.vulnMatches, arg)
	matchID := uuid.New()
	m.upsertedMatchIDs = append(m.upsertedMatchIDs, matchID)
	return dbgen.VulnMatch{ID: matchID, SnapshotID: arg.SnapshotID, ComponentID: arg.ComponentID, AdvisoryID: arg.AdvisoryID, AffectedRangeID: arg.AffectedRangeID, IsAffected: arg.IsAffected}, nil
}

func (m *mockScannerStore) MarkStaleVulnMatches(_ context.Context, arg dbgen.MarkStaleVulnMatchesParams) error {
	m.markStaleCalls = append(m.markStaleCalls, arg)
	return nil
}

func (m *mockScannerStore) CreateAuditLog(_ context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	m.auditLogs = append(m.auditLogs, arg)
	return dbgen.AuditLog{ID: uuid.New(), Action: arg.Action, ResourceID: arg.ResourceID}, nil
}

type mockCache struct {
	results      map[string][]provider.AdvisoryResult
	errs         map[string]error
	invalidated  []string
	queryHistory map[string][]provider.PackageQuery
}

func newMockCache() *mockCache {
	return &mockCache{results: map[string][]provider.AdvisoryResult{}, errs: map[string]error{}, queryHistory: map[string][]provider.PackageQuery{}}
}

func (m *mockCache) QueryWithCache(_ context.Context, prov provider.AdvisoryProvider, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	name := prov.Name()
	m.queryHistory[name] = append([]provider.PackageQuery(nil), queries...)
	if err := m.errs[name]; err != nil {
		return nil, err
	}
	return append([]provider.AdvisoryResult(nil), m.results[name]...), nil
}

func (m *mockCache) InvalidateByPackage(_ context.Context, ecosystem, packageName string) error {
	m.invalidated = append(m.invalidated, packageKey(ecosystem, packageName))
	return nil
}

type mockIngester struct {
	results map[string]map[string]uuid.UUID
	errs    map[string]error
	calls   []string
}

func newMockIngester() *mockIngester {
	return &mockIngester{results: map[string]map[string]uuid.UUID{}, errs: map[string]error{}}
}

func (m *mockIngester) Ingest(_ context.Context, providerName string, results []advisory.IngestResult) (map[string]uuid.UUID, error) {
	m.calls = append(m.calls, providerName)
	if err := m.errs[providerName]; err != nil {
		return nil, err
	}
	_ = results
	return m.results[providerName], nil
}

type mockBus struct {
	events []events.Event
}

func (m *mockBus) Publish(_ context.Context, evt events.Event) {
	m.events = append(m.events, evt)
}

type mockProvider struct {
	name string
}

func (m mockProvider) Name() string                  { return m.name }
func (m mockProvider) SupportedEcosystems() []string { return []string{"npm"} }
func (m mockProvider) QueryPackages(context.Context, []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	return nil, nil
}
func (m mockProvider) BatchSize() int { return 100 }

func TestRunScanBasicFlow(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	bus := &mockBus{}
	componentID := uuid.New()
	advisoryID := uuid.New()
	rangeID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{ID: componentID, Name: "leftpad", Version: "1.2.0", Ecosystem: "npm"}}
	store.affectedRanges[packageKey("npm", "leftpad")] = []dbgen.AffectedRange{{
		ID:          rangeID,
		AdvisoryID:  advisoryID,
		Ecosystem:   "npm",
		PackageName: "leftpad",
		Fixed:       "2.0.0",
	}}
	cache.results["osv"] = []provider.AdvisoryResult{{ProviderID: "OSV-1"}}
	ingester.results["osv"] = map[string]uuid.UUID{"OSV-1": advisoryID}

	service := New(store, cache, ingester, bus, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	scanID, err := service.RunScan(context.Background(), snapshotID, []string{"osv"}, "user")
	if err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if scanID == uuid.Nil {
		t.Fatalf("expected scan ID")
	}
	if len(store.vulnMatches) != 1 {
		t.Fatalf("expected one vuln match, got %d", len(store.vulnMatches))
	}
	if !store.vulnMatches[0].AffectedRangeID.Valid || store.vulnMatches[0].AffectedRangeID.UUID != rangeID {
		t.Fatalf("expected affected range %s, got %#v", rangeID, store.vulnMatches[0].AffectedRangeID)
	}
	if got := store.providerStatuses["osv"].Status; got != "complete" {
		t.Fatalf("expected provider status complete, got %q", got)
	}
	if len(store.markStaleCalls) != 1 {
		t.Fatalf("expected one stale cleanup call, got %d", len(store.markStaleCalls))
	}
	if got := len(store.markStaleCalls[0].FreshMatchIds); got != 1 {
		t.Fatalf("expected one fresh match ID, got %d", got)
	}
	if last := store.scanStatuses[len(store.scanStatuses)-1].Status; last != "complete" {
		t.Fatalf("expected final scan status complete, got %q", last)
	}
	if len(bus.events) == 0 || bus.events[len(bus.events)-1].Type != events.ScanCompleted {
		t.Fatalf("expected scan completed event, got %#v", bus.events)
	}
}

func TestRunScanPartialProviderFailure(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	bus := &mockBus{}
	componentID := uuid.New()
	advisoryID := uuid.New()
	rangeID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{ID: componentID, Name: "leftpad", Version: "1.2.0", Ecosystem: "npm"}}
	store.affectedRanges[packageKey("npm", "leftpad")] = []dbgen.AffectedRange{{ID: rangeID, AdvisoryID: advisoryID, Ecosystem: "npm", PackageName: "leftpad", Fixed: "2.0.0"}}
	cache.results["osv"] = []provider.AdvisoryResult{{ProviderID: "OSV-1"}}
	cache.errs["nvd"] = errors.New("provider failed")
	ingester.results["osv"] = map[string]uuid.UUID{"OSV-1": advisoryID}

	service := New(store, cache, ingester, bus, map[string]provider.AdvisoryProvider{
		"osv": mockProvider{name: "osv"},
		"nvd": mockProvider{name: "nvd"},
	}, zerolog.Nop())

	if _, err := service.RunScan(context.Background(), snapshotID, []string{"osv", "nvd"}, "user"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if got := store.providerStatuses["osv"].Status; got != "complete" {
		t.Fatalf("expected osv to complete, got %q", got)
	}
	if got := store.providerStatuses["nvd"].Status; got != "failed" {
		t.Fatalf("expected nvd to fail, got %q", got)
	}
	if len(store.markStaleCalls) != 1 {
		t.Fatalf("expected stale cleanup after partial success, got %d calls", len(store.markStaleCalls))
	}
	if got := len(store.markStaleCalls[0].FreshMatchIds); got != 1 {
		t.Fatalf("expected one fresh match ID after partial success, got %d", got)
	}
	if last := store.scanStatuses[len(store.scanStatuses)-1].Status; last != "complete" {
		t.Fatalf("expected final scan status complete, got %q", last)
	}
}

func TestRunScanDoesNotMarkStaleMatchesWhenNoProvidersResolve(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	bus := &mockBus{}
	snapshotID := uuid.New()

	service := New(store, cache, ingester, bus, nil, zerolog.Nop())
	_, err := service.RunScan(context.Background(), snapshotID, nil, "system")
	if err == nil || err.Error() != "all providers failed" {
		t.Fatalf("expected all providers failed error, got %v", err)
	}
	if len(store.markStaleCalls) != 0 {
		t.Fatalf("expected no stale cleanup calls when no providers resolve, got %d", len(store.markStaleCalls))
	}
	if last := store.scanStatuses[len(store.scanStatuses)-1].Status; last != "failed" {
		t.Fatalf("expected final scan status failed, got %q", last)
	}
	if len(bus.events) == 0 || bus.events[len(bus.events)-1].Type != events.ScanFailed {
		t.Fatalf("expected scan failed event, got %#v", bus.events)
	}
}

func TestRunScanEmptySnapshot(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	bus := &mockBus{}
	service := New(store, cache, ingester, bus, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())

	if _, err := service.RunScan(context.Background(), uuid.New(), []string{"osv"}, "system"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if len(store.vulnMatches) != 0 {
		t.Fatalf("expected no vuln matches, got %d", len(store.vulnMatches))
	}
	if last := store.scanStatuses[len(store.scanStatuses)-1].Status; last != "complete" {
		t.Fatalf("expected final scan status complete, got %q", last)
	}
	if got := len(cache.queryHistory["osv"]); got != 0 {
		t.Fatalf("expected empty package query list, got %d", got)
	}
}

func TestRunScanSkipsNonMatchingVersion(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	componentID := uuid.New()
	advisoryID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{ID: componentID, Name: "leftpad", Version: "2.1.0", Ecosystem: "npm"}}
	store.affectedRanges[packageKey("npm", "leftpad")] = []dbgen.AffectedRange{{
		ID:          uuid.New(),
		AdvisoryID:  advisoryID,
		Ecosystem:   "npm",
		PackageName: "leftpad",
		Fixed:       "2.0.0",
	}}
	cache.results["osv"] = []provider.AdvisoryResult{{ProviderID: "OSV-1"}}
	ingester.results["osv"] = map[string]uuid.UUID{"OSV-1": advisoryID}

	service := New(store, cache, ingester, &mockBus{}, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	if _, err := service.RunScan(context.Background(), snapshotID, []string{"osv"}, "user"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if len(store.vulnMatches) != 0 {
		t.Fatalf("expected no vuln matches, got %d", len(store.vulnMatches))
	}
	if len(store.markStaleCalls) != 1 {
		t.Fatalf("expected one stale cleanup call, got %d", len(store.markStaleCalls))
	}
	if got := len(store.markStaleCalls[0].FreshMatchIds); got != 0 {
		t.Fatalf("expected zero fresh match IDs, got %d", got)
	}
}

func TestTriggerRescanInvalidatesCacheAndWritesAuditLog(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	componentID := uuid.New()
	advisoryID := uuid.New()
	actorID := uuid.New()
	orgID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{ID: componentID, Name: "leftpad", Version: "1.2.0", Ecosystem: "npm"}}
	store.affectedRanges[packageKey("npm", "leftpad")] = []dbgen.AffectedRange{{ID: uuid.New(), AdvisoryID: advisoryID, Ecosystem: "npm", PackageName: "leftpad", Fixed: "2.0.0"}}
	cache.results["osv"] = []provider.AdvisoryResult{{ProviderID: "OSV-1"}}
	ingester.results["osv"] = map[string]uuid.UUID{"OSV-1": advisoryID}

	service := New(store, cache, ingester, &mockBus{}, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	_, err := service.TriggerRescan(context.Background(), snapshotID, []string{"osv"}, audit.Entry{
		ActorID:      &actorID,
		ActorType:    audit.ActorUser,
		ActorDisplay: "alice",
		OrgID:        &orgID,
		IPAddress:    "127.0.0.1",
		UserAgent:    "test",
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("TriggerRescan returned error: %v", err)
	}
	if len(cache.invalidated) != 1 || cache.invalidated[0] != packageKey("npm", "leftpad") {
		t.Fatalf("expected cache invalidation for leftpad, got %#v", cache.invalidated)
	}
	if len(store.auditLogs) != 1 {
		t.Fatalf("expected one audit log entry, got %d", len(store.auditLogs))
	}
	if store.auditLogs[0].Action != audit.ActionScanTrigger {
		t.Fatalf("expected audit action %q, got %q", audit.ActionScanTrigger, store.auditLogs[0].Action)
	}
	if !store.auditLogs[0].ActorID.Valid || store.auditLogs[0].ActorID.UUID != actorID {
		t.Fatalf("expected actor ID %s, got %#v", actorID, store.auditLogs[0].ActorID)
	}
	if !store.auditLogs[0].OrgID.Valid || store.auditLogs[0].OrgID.UUID != orgID {
		t.Fatalf("expected org ID %s, got %#v", orgID, store.auditLogs[0].OrgID)
	}
	_ = sql.ErrNoRows
}
