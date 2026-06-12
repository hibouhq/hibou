package advisory

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type mockIngesterStore struct {
	root          *mockIngesterStore
	txDB          *sql.DB
	txScoped      bool
	beginTxCalled int
	withTxCalled  int
	txScopedCalls int
	upsertErrs    map[string]error
	canonicalIDs  map[string]uuid.UUID
	advisories    map[uuid.UUID]dbgen.Advisory
	aliases       map[string]uuid.UUID
	sources       map[uuid.UUID]map[string]dbgen.AdvisorySource
	ranges        map[uuid.UUID][]dbgen.AffectedRange
}

func newMockIngesterStore() *mockIngesterStore {
	return &mockIngesterStore{
		upsertErrs:   map[string]error{},
		canonicalIDs: map[string]uuid.UUID{},
		advisories:   map[uuid.UUID]dbgen.Advisory{},
		aliases:      map[string]uuid.UUID{},
		sources:      map[uuid.UUID]map[string]dbgen.AdvisorySource{},
		ranges:       map[uuid.UUID][]dbgen.AffectedRange{},
	}
}

func (m *mockIngesterStore) state() *mockIngesterStore {
	if m.root != nil {
		return m.root
	}
	return m
}

func (m *mockIngesterStore) recordTxScopedCall() {
	if m.txScoped {
		m.state().txScopedCalls++
	}
}

func (m *mockIngesterStore) GetAdvisoryByAlias(_ context.Context, alias string) (dbgen.Advisory, error) {
	id, ok := m.aliases[alias]
	if !ok {
		return dbgen.Advisory{}, sql.ErrNoRows
	}
	return m.advisories[id], nil
}

func (m *mockIngesterStore) BeginTx(context.Context) (*sql.Tx, error) {
	state := m.state()
	state.beginTxCalled++
	if state.txDB == nil {
		return nil, nil
	}
	return state.txDB.BeginTx(context.Background(), nil)
}

func (m *mockIngesterStore) WithTx(_ *sql.Tx) IngesterStore {
	state := m.state()
	state.withTxCalled++
	return &mockIngesterStore{
		root:         state,
		txScoped:     true,
		upsertErrs:   state.upsertErrs,
		canonicalIDs: state.canonicalIDs,
		advisories:   state.advisories,
		aliases:      state.aliases,
		sources:      state.sources,
		ranges:       state.ranges,
	}
}

func (m *mockIngesterStore) UpsertAdvisory(_ context.Context, arg dbgen.UpsertAdvisoryParams) (dbgen.Advisory, error) {
	m.recordTxScopedCall()
	if err := m.state().upsertErrs[arg.CanonicalID]; err != nil {
		return dbgen.Advisory{}, err
	}
	id, ok := m.canonicalIDs[arg.CanonicalID]
	if !ok {
		id = uuid.New()
		m.canonicalIDs[arg.CanonicalID] = id
	}
	current := m.advisories[id]
	current.ID = id
	current.CanonicalID = arg.CanonicalID
	current.Title = arg.Title
	current.Description = arg.Description
	current.Severity = arg.Severity
	current.CvssScore = arg.CvssScore
	current.CvssVersion = arg.CvssVersion
	current.CvssVector = arg.CvssVector
	current.CweIds = append([]string(nil), arg.CweIds...)
	current.IsMalware = arg.IsMalware
	current.MalwareType = arg.MalwareType
	current.PublishedAt = arg.PublishedAt
	current.WithdrawnAt = arg.WithdrawnAt
	if current.CreatedAt.IsZero() {
		current.CreatedAt = time.Now().UTC()
	}
	current.UpdatedAt = time.Now().UTC()
	m.advisories[id] = current
	return current, nil
}

func (m *mockIngesterStore) UpdateAdvisoryCanonicalID(_ context.Context, arg dbgen.UpdateAdvisoryCanonicalIDParams) error {
	m.recordTxScopedCall()
	current, ok := m.advisories[arg.AdvisoryID]
	if !ok {
		return sql.ErrNoRows
	}
	delete(m.canonicalIDs, current.CanonicalID)
	current.CanonicalID = arg.CanonicalID
	current.UpdatedAt = time.Now().UTC()
	m.advisories[arg.AdvisoryID] = current
	m.canonicalIDs[arg.CanonicalID] = arg.AdvisoryID
	return nil
}

func (m *mockIngesterStore) UpsertAdvisoryAlias(_ context.Context, arg dbgen.UpsertAdvisoryAliasParams) error {
	m.recordTxScopedCall()
	m.aliases[arg.Alias] = arg.AdvisoryID
	return nil
}

func (m *mockIngesterStore) UpsertAdvisorySource(_ context.Context, arg dbgen.UpsertAdvisorySourceParams) error {
	m.recordTxScopedCall()
	if _, ok := m.sources[arg.AdvisoryID]; !ok {
		m.sources[arg.AdvisoryID] = map[string]dbgen.AdvisorySource{}
	}
	current, ok := m.sources[arg.AdvisoryID][arg.Provider]
	if !ok {
		current.ID = uuid.New()
		current.CreatedAt = time.Now().UTC()
	}
	current.AdvisoryID = arg.AdvisoryID
	current.Provider = arg.Provider
	current.ProviderID = arg.ProviderID
	current.Severity = arg.Severity
	current.CvssScore = arg.CvssScore
	current.CvssVersion = arg.CvssVersion
	current.CvssVector = arg.CvssVector
	current.RawData = arg.RawData
	current.FetchedAt = arg.FetchedAt
	m.sources[arg.AdvisoryID][arg.Provider] = current
	return nil
}

func (m *mockIngesterStore) ListSourcesByAdvisory(_ context.Context, advisoryID uuid.UUID) ([]dbgen.AdvisorySource, error) {
	providerSources := m.sources[advisoryID]
	items := make([]dbgen.AdvisorySource, 0, len(providerSources))
	for _, source := range providerSources {
		items = append(items, source)
	}
	return items, nil
}

func (m *mockIngesterStore) CreateAffectedRange(_ context.Context, arg dbgen.CreateAffectedRangeParams) (dbgen.AffectedRange, error) {
	m.recordTxScopedCall()
	created := dbgen.AffectedRange{
		ID:           uuid.New(),
		AdvisoryID:   arg.AdvisoryID,
		Ecosystem:    arg.Ecosystem,
		PackageName:  arg.PackageName,
		Introduced:   arg.Introduced,
		Fixed:        arg.Fixed,
		LastAffected: arg.LastAffected,
		Source:       arg.Source,
		CreatedAt:    time.Now().UTC(),
	}
	m.ranges[arg.AdvisoryID] = append(m.ranges[arg.AdvisoryID], created)
	return created, nil
}

func (m *mockIngesterStore) DeleteAffectedRangesByAdvisoryAndSource(_ context.Context, arg dbgen.DeleteAffectedRangesByAdvisoryAndSourceParams) error {
	m.recordTxScopedCall()
	filtered := m.ranges[arg.AdvisoryID][:0]
	for _, affectedRange := range m.ranges[arg.AdvisoryID] {
		if affectedRange.Source != arg.Source {
			filtered = append(filtered, affectedRange)
		}
	}
	m.ranges[arg.AdvisoryID] = filtered
	return nil
}

func TestIngesterIngestUsesTransactionAndCommits(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectCommit()

	store := newMockIngesterStore()
	store.txDB = db
	ingester := NewIngester(store, zerolog.Nop())
	ingester.withTx = func(tx *sql.Tx) IngesterStore {
		return store.WithTx(tx)
	}

	_, err = ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID: "GHSA-tx-commit",
		Aliases:    []string{"GHSA-tx-commit"},
		Title:      "transactional advisory",
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if store.beginTxCalled != 1 {
		t.Fatalf("expected BeginTx to be called once, got %d", store.beginTxCalled)
	}
	if store.withTxCalled != 1 {
		t.Fatalf("expected WithTx to be called once, got %d", store.withTxCalled)
	}
	if store.txScopedCalls == 0 {
		t.Fatalf("expected transactional query set to be used")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestIngesterIngestRollsBackTransactionOnWriteFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New returned error: %v", err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectRollback()

	store := newMockIngesterStore()
	store.txDB = db
	store.upsertErrs["GHSA-tx-rollback"] = errors.New("upsert failed")
	ingester := NewIngester(store, zerolog.Nop())
	ingester.withTx = func(tx *sql.Tx) IngesterStore {
		return store.WithTx(tx)
	}

	_, err = ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID: "GHSA-tx-rollback",
		Aliases:    []string{"GHSA-tx-rollback"},
		Title:      "rollback advisory",
	}})
	if err == nil || !errors.Is(err, store.upsertErrs["GHSA-tx-rollback"]) {
		t.Fatalf("expected upsert failure, got %v", err)
	}
	if store.beginTxCalled != 1 {
		t.Fatalf("expected BeginTx to be called once, got %d", store.beginTxCalled)
	}
	if store.withTxCalled != 1 {
		t.Fatalf("expected WithTx to be called once, got %d", store.withTxCalled)
	}
	if store.txScopedCalls == 0 {
		t.Fatalf("expected transactional query set to be used before rollback")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestIngesterIngestNewAdvisory(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())
	severity := SeverityHigh
	score := 7.4
	version := CVSSVersionV31
	publishedAt := time.Now().UTC().Truncate(time.Second)

	ids, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID:  "GHSA-1111",
		Aliases:     []string{"CVE-2026-1111", "GHSA-1111"},
		Title:       "leftpad advisory",
		Description: "desc",
		Severity:    &severity,
		CVSSScore:   &score,
		CVSSVersion: &version,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CWEIDs:      []string{"CWE-79"},
		PublishedAt: &publishedAt,
		AffectedRanges: []AffectedRange{{
			Ecosystem:   "npm",
			PackageName: "leftpad",
			Fixed:       "1.0.1",
		}},
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}

	advisoryID, ok := ids["GHSA-1111"]
	if !ok {
		t.Fatalf("expected advisory ID for provider result")
	}

	stored := store.advisories[advisoryID]
	if stored.CanonicalID != "CVE-2026-1111" {
		t.Fatalf("expected canonical ID to prefer CVE alias, got %q", stored.CanonicalID)
	}
	if stored.Severity != dbgen.SeverityLevelHigh {
		t.Fatalf("expected severity high, got %q", stored.Severity)
	}
	if !stored.CvssScore.Valid || stored.CvssScore.String != "7.4" {
		t.Fatalf("expected cvss score to be stored, got %#v", stored.CvssScore)
	}
	if got := store.aliases["GHSA-1111"]; got != advisoryID {
		t.Fatalf("expected provider ID alias to be recorded, got %s", got)
	}
	if got := store.aliases["CVE-2026-1111"]; got != advisoryID {
		t.Fatalf("expected CVE alias to be recorded, got %s", got)
	}
	if len(store.ranges[advisoryID]) != 1 {
		t.Fatalf("expected one affected range, got %d", len(store.ranges[advisoryID]))
	}
}

func TestIngesterIngestExistingAdvisoryMergesSeverity(t *testing.T) {
	store := newMockIngesterStore()
	existingID := uuid.New()
	store.canonicalIDs["GHSA-existing"] = existingID
	store.advisories[existingID] = dbgen.Advisory{
		ID:          existingID,
		CanonicalID: "GHSA-existing",
		Title:       "existing",
		Severity:    dbgen.SeverityLevelHigh,
	}
	store.aliases["GHSA-existing"] = existingID
	store.sources[existingID] = map[string]dbgen.AdvisorySource{
		"github": {
			ID:         uuid.New(),
			AdvisoryID: existingID,
			Provider:   "github",
			ProviderID: "GHSA-existing",
			CvssScore:  sql.NullString{String: "7.2", Valid: true},
		},
	}

	ingester := NewIngester(store, zerolog.Nop())
	score := 9.8
	version := CVSSVersionV31
	severity := SeverityCritical
	ids, err := ingester.Ingest(context.Background(), "nvd", []IngestResult{{
		ProviderID:  "CVE-2026-2222",
		Aliases:     []string{"GHSA-existing", "CVE-2026-2222"},
		Title:       "updated",
		Severity:    &severity,
		CVSSScore:   &score,
		CVSSVersion: &version,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}

	if ids["CVE-2026-2222"] != existingID {
		t.Fatalf("expected existing advisory ID to be reused")
	}
	stored := store.advisories[existingID]
	if stored.CanonicalID != "CVE-2026-2222" {
		t.Fatalf("expected canonical ID to promote to CVE, got %q", stored.CanonicalID)
	}
	if stored.Severity != dbgen.SeverityLevelCritical {
		t.Fatalf("expected merged severity critical, got %q", stored.Severity)
	}
	if !stored.CvssScore.Valid || stored.CvssScore.String != "9.8" {
		t.Fatalf("expected merged score 9.8, got %#v", stored.CvssScore)
	}
	if !stored.CvssVersion.Valid || stored.CvssVersion.CvssVersion != dbgen.CvssVersionV31 {
		t.Fatalf("expected merged CVSS version v3.1, got %#v", stored.CvssVersion)
	}
	if got := store.aliases["CVE-2026-2222"]; got != existingID {
		t.Fatalf("expected new alias to point to existing advisory, got %s", got)
	}
	if got := store.aliases["GHSA-existing"]; got != existingID {
		t.Fatalf("expected existing GHSA alias to remain attached, got %s", got)
	}
}

func TestIngesterIngestMalwareDetection(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())
	malwareType := "dependency confusion"

	ids, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID:     "MAL-2026-1",
		Title:          "malware",
		IsMalware:      true,
		MalwareType:    &malwareType,
		AffectedRanges: []AffectedRange{{Ecosystem: "npm", PackageName: "evilpkg"}},
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}

	stored := store.advisories[ids["MAL-2026-1"]]
	if !stored.IsMalware {
		t.Fatalf("expected advisory to be marked as malware")
	}
	if !stored.MalwareType.Valid || stored.MalwareType.MalwareType != dbgen.MalwareTypeDependencyConfusion {
		t.Fatalf("expected malware type dependency_confusion, got %#v", stored.MalwareType)
	}
}

func TestIngesterFindExistingAdvisoryPropagatesLookupErrors(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(erroringAliasStore{mockIngesterStore: store}, zerolog.Nop())
	_, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{ProviderID: "GHSA-err"}})
	if err == nil || !errors.Is(err, errAliasLookup) {
		t.Fatalf("expected alias lookup error, got %v", err)
	}
}

var errAliasLookup = errors.New("alias lookup failed")

type erroringAliasStore struct {
	*mockIngesterStore
}

func (e erroringAliasStore) GetAdvisoryByAlias(context.Context, string) (dbgen.Advisory, error) {
	return dbgen.Advisory{}, errAliasLookup
}
