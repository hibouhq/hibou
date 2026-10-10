package scanner

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type mockScannerStore struct {
	components       []dbgen.Component
	affectedRanges   map[string][]dbgen.AffectedRange
	scanStatuses     []dbgen.UpdateScanStatusParams
	providerStatuses map[string]dbgen.UpdateScanProviderParams
	vulnerabilities  []dbgen.CreateVulnerabilityParams
	markStaleCalls   []struct {
		SnapshotID uuid.UUID
		VulnType   string
		FreshIDs   []uuid.UUID
	}
	createdVulnIDs []uuid.UUID
	auditLogs      []dbgen.CreateAuditLogParams
	createdScanID  uuid.UUID
	providerIDs    map[string]uuid.UUID
	advisories     map[uuid.UUID]dbgen.Advisory
}

func newMockScannerStore() *mockScannerStore {
	return &mockScannerStore{
		affectedRanges:   map[string][]dbgen.AffectedRange{},
		providerStatuses: map[string]dbgen.UpdateScanProviderParams{},
		providerIDs:      map[string]uuid.UUID{},
		advisories:       map[uuid.UUID]dbgen.Advisory{},
	}
}

func freshCountForType(calls []struct {
	SnapshotID uuid.UUID
	VulnType   string
	FreshIDs   []uuid.UUID
}, vulnType string) int {
	for _, call := range calls {
		if call.VulnType == vulnType {
			return len(call.FreshIDs)
		}
	}
	return -1
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

// ListAdvisoryRatings serves each mock advisory's headline as one rating, so
// matched findings take the advisory's severity as before ADR-038.
func (m *mockScannerStore) ListAdvisoryRatings(_ context.Context, ids []uuid.UUID) ([]dbgen.ListAdvisoryRatingsRow, error) {
	rows := []dbgen.ListAdvisoryRatingsRow{}
	for _, id := range ids {
		if advisory, ok := m.advisories[id]; ok && advisory.Severity != "" {
			rows = append(rows, dbgen.ListAdvisoryRatingsRow{
				AdvisoryID: id, Provider: "osv", Rater: "nvd",
				Label: dbgen.NullSeverityLevel{SeverityLevel: advisory.Severity, Valid: true},
			})
		}
	}
	return rows, nil
}

func (m *mockScannerStore) GetAdvisoryByID(_ context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	if advisory, ok := m.advisories[id]; ok {
		return advisory, nil
	}
	return dbgen.Advisory{}, nil
}

func (m *mockScannerStore) CreateVulnerability(_ context.Context, arg dbgen.CreateVulnerabilityParams) (*store.Vulnerability, error) {
	m.vulnerabilities = append(m.vulnerabilities, arg)
	vulnID := uuid.New()
	m.createdVulnIDs = append(m.createdVulnIDs, vulnID)
	vulnerability := &store.Vulnerability{
		ID:                     vulnID,
		Type:                   arg.Type,
		SnapshotID:             arg.SnapshotID,
		Severity:               arg.Severity,
		ScannerName:            arg.ScannerName,
		Fingerprint:            arg.Fingerprint,
		PrimaryIdentifierValue: arg.PrimaryIdentifierValue,
	}
	if arg.ComponentID.Valid {
		vulnerability.ComponentID = &arg.ComponentID.UUID
	}
	if arg.AdvisoryID.Valid {
		vulnerability.AdvisoryID = &arg.AdvisoryID.UUID
	}
	if arg.AffectedRangeID.Valid {
		vulnerability.AffectedRangeID = &arg.AffectedRangeID.UUID
	}
	return vulnerability, nil
}

func (m *mockScannerStore) GetSnapshotByID(_ context.Context, _ uuid.UUID) (*store.Snapshot, error) {
	return nil, nil
}

func (m *mockScannerStore) GetRefByID(_ context.Context, _ uuid.UUID) (*store.Ref, error) {
	return nil, nil
}

func (m *mockScannerStore) GetRepositoryByID(_ context.Context, _ uuid.UUID) (*store.Repository, error) {
	return nil, nil
}

func (m *mockScannerStore) ClearFindingsNotified(_ context.Context, _ string, _ uuid.UUID, _ []string) error {
	return nil
}

func (m *mockScannerStore) GetSnapshotCodeRefs(_ context.Context, _ uuid.UUID) (*store.SnapshotCodeRefs, error) {
	return nil, nil
}

func (m *mockScannerStore) ApplyReachabilityFromCodeRefs(_ context.Context, _ uuid.UUID, _ store.SnapshotCodeRefs) (int64, int64, error) {
	return 0, 0, nil
}

func (m *mockScannerStore) MarkStaleVulnerabilities(_ context.Context, snapshotID uuid.UUID, vulnType string, freshIDs []uuid.UUID) ([]string, error) {
	m.markStaleCalls = append(m.markStaleCalls, struct {
		SnapshotID uuid.UUID
		VulnType   string
		FreshIDs   []uuid.UUID
	}{
		SnapshotID: snapshotID,
		VulnType:   vulnType,
		FreshIDs:   append([]uuid.UUID(nil), freshIDs...),
	})
	return nil, nil
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
	store.advisories[advisoryID] = dbgen.Advisory{ID: advisoryID, CanonicalID: "OSV-1", Severity: dbgen.SeverityLevelHigh}
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
	if len(store.vulnerabilities) != 1 {
		t.Fatalf("expected one vulnerability, got %d", len(store.vulnerabilities))
	}
	if !store.vulnerabilities[0].AffectedRangeID.Valid || store.vulnerabilities[0].AffectedRangeID.UUID != rangeID {
		t.Fatalf("expected affected range %s, got %#v", rangeID, store.vulnerabilities[0].AffectedRangeID)
	}
	if got := store.providerStatuses["osv"].Status; got != "complete" {
		t.Fatalf("expected provider status complete, got %q", got)
	}
	if len(store.markStaleCalls) != 2 {
		t.Fatalf("expected two stale cleanup calls, got %d", len(store.markStaleCalls))
	}
	if got := freshCountForType(store.markStaleCalls, "dependency"); got != 1 {
		t.Fatalf("expected one fresh dependency vulnerability ID, got %d", got)
	}
	if got := freshCountForType(store.markStaleCalls, "malware"); got != 0 {
		t.Fatalf("expected zero fresh malware vulnerability IDs, got %d", got)
	}
	if last := store.scanStatuses[len(store.scanStatuses)-1].Status; last != "complete" {
		t.Fatalf("expected final scan status complete, got %q", last)
	}
	if len(bus.events) == 0 || bus.events[0].Type != events.ScanCompleted {
		t.Fatalf("expected scan completed event first, got %#v", bus.events)
	}
	if bus.events[len(bus.events)-1].Type != events.VulnerabilitiesFound {
		t.Fatalf("expected vulnerabilities.found batch event, got %#v", bus.events)
	}
}

// A scan whose batch mixes malware and ordinary findings must emit TWO events:
// the generic vulnerabilities.found without the malware identifiers, and one
// malware.detected carrying only them — malware never drowns in the batch.
func TestRunScanSplitsMalwareIntoOwnEvent(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	bus := &mockBus{}
	componentID := uuid.New()
	depAdvisoryID := uuid.New()
	malAdvisoryID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{ID: componentID, Name: "leftpad", Version: "1.2.0", Ecosystem: "npm"}}
	store.affectedRanges[packageKey("npm", "leftpad")] = []dbgen.AffectedRange{
		{ID: uuid.New(), AdvisoryID: depAdvisoryID, Ecosystem: "npm", PackageName: "leftpad", Fixed: "2.0.0"},
		{ID: uuid.New(), AdvisoryID: malAdvisoryID, Ecosystem: "npm", PackageName: "leftpad", Fixed: "9.9.9"},
	}
	store.advisories[depAdvisoryID] = dbgen.Advisory{ID: depAdvisoryID, CanonicalID: "CVE-2024-0001", Severity: dbgen.SeverityLevelHigh}
	store.advisories[malAdvisoryID] = dbgen.Advisory{ID: malAdvisoryID, CanonicalID: "MAL-2025-0001", Severity: dbgen.SeverityLevelCritical, IsMalware: true}
	cache.results["osv"] = []provider.AdvisoryResult{{ProviderID: "CVE-2024-0001"}, {ProviderID: "MAL-2025-0001"}}
	ingester.results["osv"] = map[string]uuid.UUID{"CVE-2024-0001": depAdvisoryID, "MAL-2025-0001": malAdvisoryID}

	service := New(store, cache, ingester, bus, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	if _, err := service.RunScan(context.Background(), snapshotID, []string{"osv"}, "user"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}

	identifiersByEvent := map[events.Type][]string{}
	for _, event := range bus.events {
		payload, ok := event.Payload.(map[string]any)
		if !ok {
			continue
		}
		if identifiers, ok := payload["identifiers"].([]string); ok {
			identifiersByEvent[event.Type] = identifiers
		}
	}
	if got := identifiersByEvent[events.VulnerabilitiesFound]; len(got) != 1 || got[0] != "CVE-2024-0001" {
		t.Fatalf("vulnerabilities.found identifiers = %v, want [CVE-2024-0001]", got)
	}
	if got := identifiersByEvent[events.MalwareDetected]; len(got) != 1 || got[0] != "MAL-2025-0001" {
		t.Fatalf("malware.detected identifiers = %v, want [MAL-2025-0001]", got)
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
	store.advisories[advisoryID] = dbgen.Advisory{ID: advisoryID, CanonicalID: "OSV-1", Severity: dbgen.SeverityLevelHigh}
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
	if len(store.markStaleCalls) != 2 {
		t.Fatalf("expected stale cleanup for both vulnerability types after partial success, got %d calls", len(store.markStaleCalls))
	}
	if got := freshCountForType(store.markStaleCalls, "dependency"); got != 1 {
		t.Fatalf("expected one fresh dependency vulnerability ID after partial success, got %d", got)
	}
	if got := freshCountForType(store.markStaleCalls, "malware"); got != 0 {
		t.Fatalf("expected zero fresh malware vulnerability IDs after partial success, got %d", got)
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
	if len(store.vulnerabilities) != 0 {
		t.Fatalf("expected no vulnerabilities, got %d", len(store.vulnerabilities))
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
	store.advisories[advisoryID] = dbgen.Advisory{ID: advisoryID, CanonicalID: "OSV-1", Severity: dbgen.SeverityLevelHigh}
	cache.results["osv"] = []provider.AdvisoryResult{{ProviderID: "OSV-1"}}
	ingester.results["osv"] = map[string]uuid.UUID{"OSV-1": advisoryID}

	service := New(store, cache, ingester, &mockBus{}, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	if _, err := service.RunScan(context.Background(), snapshotID, []string{"osv"}, "user"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if len(store.vulnerabilities) != 0 {
		t.Fatalf("expected no vulnerabilities, got %d", len(store.vulnerabilities))
	}
	if len(store.markStaleCalls) != 2 {
		t.Fatalf("expected two stale cleanup calls, got %d", len(store.markStaleCalls))
	}
	if got := freshCountForType(store.markStaleCalls, "dependency"); got != 0 {
		t.Fatalf("expected zero fresh dependency vulnerability IDs, got %d", got)
	}
	if got := freshCountForType(store.markStaleCalls, "malware"); got != 0 {
		t.Fatalf("expected zero fresh malware vulnerability IDs, got %d", got)
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

// A finding must be attributed to whatever produced the range that matched it,
// not to the pass that happened to notice it. Ranges a person authored are
// matched by the same query as OSV's, so without this a human decision is
// reported as having come from an advisory database — provenance that is wrong
// rather than merely vague.
func TestAttributionFollowsTheRangeSource(t *testing.T) {
	cases := []struct {
		name        string
		provider    string
		rangeSource string
		want        string
	}{
		{"authored here", "osv", "triage", "triage"},
		{"authored, scoped source", "trivy", "triage:instance", "triage:instance"},
		{"ordinary provider range", "osv", "osv", "osv"},
		{"range from another provider", "osv", "trivy", "osv"},
		{"range with no source recorded", "osv", "", "osv"},
		{"a provider merely named like triage", "osv", "triagebot", "osv"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := attributionFor(testCase.provider, testCase.rangeSource); got != testCase.want {
				t.Errorf("attributionFor(%q, %q) = %q, want %q",
					testCase.provider, testCase.rangeSource, got, testCase.want)
			}
		})
	}
}

// A range authored by triage (ADR-028) has no provider echo — no upstream
// database carries its coordinates, which is why it was authored at all. The
// scan must match it from the stored ranges even when every provider returns
// nothing for the snapshot.
func TestRunScanMatchesTriageAuthoredRangesWithoutProviderEcho(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	componentID := uuid.New()
	advisoryID := uuid.New()
	rangeID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{
		ID: componentID, Name: "org.apache.tomcat:tomcat-catalina", Version: "11.0.22", Ecosystem: "maven",
	}}
	store.affectedRanges[packageKey("maven", "org.apache.tomcat:tomcat-catalina")] = []dbgen.AffectedRange{{
		ID:           rangeID,
		AdvisoryID:   advisoryID,
		Ecosystem:    "maven",
		PackageName:  "org.apache.tomcat:tomcat-catalina",
		Introduced:   "11.0.0-M1",
		LastAffected: "11.0.22",
		Source:       "triage",
	}}
	store.advisories[advisoryID] = dbgen.Advisory{ID: advisoryID, CanonicalID: "CVE-2026-53434", Severity: dbgen.SeverityLevelCritical}
	// The provider returns nothing: the CVE has no package coordinates upstream.
	cache.results["osv"] = nil
	ingester.results["osv"] = map[string]uuid.UUID{}

	service := New(store, cache, ingester, &mockBus{}, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	if _, err := service.RunScan(context.Background(), snapshotID, []string{"osv"}, "user"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if len(store.vulnerabilities) != 1 {
		t.Fatalf("expected one vulnerability from the authored range, got %d", len(store.vulnerabilities))
	}
	finding := store.vulnerabilities[0]
	if finding.ScannerName != "triage" {
		t.Errorf("scanner_name = %q, want %q", finding.ScannerName, "triage")
	}
	if finding.PrimaryIdentifierValue != "CVE-2026-53434" {
		t.Errorf("identifier = %q, want the CVE", finding.PrimaryIdentifierValue)
	}
	if !finding.AffectedRangeID.Valid || finding.AffectedRangeID.UUID != rangeID {
		t.Errorf("affected range = %#v, want %s", finding.AffectedRangeID, rangeID)
	}
	// The finding must count as fresh, or the same pass's stale sweep would
	// resolve it moments after creating it.
	if got := freshCountForType(store.markStaleCalls, "dependency"); got != 1 {
		t.Errorf("fresh dependency IDs = %d, want 1", got)
	}
}

// A withdrawn advisory's authored ranges stay in the store until the review
// pass retires them; matching must not resurrect the finding meanwhile.
func TestRunScanSkipsWithdrawnTriageAuthoredAdvisories(t *testing.T) {
	store := newMockScannerStore()
	cache := newMockCache()
	ingester := newMockIngester()
	advisoryID := uuid.New()
	snapshotID := uuid.New()

	store.components = []dbgen.Component{{
		ID: uuid.New(), Name: "org.apache.tomcat:tomcat-catalina", Version: "11.0.22", Ecosystem: "maven",
	}}
	store.affectedRanges[packageKey("maven", "org.apache.tomcat:tomcat-catalina")] = []dbgen.AffectedRange{{
		ID:           uuid.New(),
		AdvisoryID:   advisoryID,
		Ecosystem:    "maven",
		PackageName:  "org.apache.tomcat:tomcat-catalina",
		Introduced:   "11.0.0-M1",
		LastAffected: "11.0.22",
		Source:       "triage",
	}}
	store.advisories[advisoryID] = dbgen.Advisory{
		ID: advisoryID, CanonicalID: "CVE-2026-53434", Severity: dbgen.SeverityLevelCritical,
		WithdrawnAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	cache.results["osv"] = nil
	ingester.results["osv"] = map[string]uuid.UUID{}

	service := New(store, cache, ingester, &mockBus{}, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	if _, err := service.RunScan(context.Background(), snapshotID, []string{"osv"}, "user"); err != nil {
		t.Fatalf("RunScan returned error: %v", err)
	}
	if len(store.vulnerabilities) != 0 {
		t.Fatalf("expected no findings from a withdrawn advisory, got %d", len(store.vulnerabilities))
	}
}
