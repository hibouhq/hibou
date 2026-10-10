package advisory

import (
	"context"
	"database/sql"
	"errors"
	"slices"
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
	ratings       map[uuid.UUID]dbgen.SyncAdvisorySourceRatingsParams
	ranges        map[uuid.UUID][]dbgen.AffectedRange
	cwes          map[uuid.UUID][]int
}

func newMockIngesterStore() *mockIngesterStore {
	return &mockIngesterStore{
		upsertErrs:   map[string]error{},
		canonicalIDs: map[string]uuid.UUID{},
		advisories:   map[uuid.UUID]dbgen.Advisory{},
		aliases:      map[string]uuid.UUID{},
		sources:      map[uuid.UUID]map[string]dbgen.AdvisorySource{},
		ratings:      map[uuid.UUID]dbgen.SyncAdvisorySourceRatingsParams{},
		ranges:       map[uuid.UUID][]dbgen.AffectedRange{},
		cwes:         map[uuid.UUID][]int{},
	}
}

func (m *mockIngesterStore) GetAdvisoryByID(_ context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	advisory, ok := m.state().advisories[id]
	if !ok {
		return dbgen.Advisory{}, sql.ErrNoRows
	}
	return advisory, nil
}

func (m *mockIngesterStore) SyncAdvisorySourceRatings(_ context.Context, arg dbgen.SyncAdvisorySourceRatingsParams) error {
	m.state().ratings[arg.AdvisorySourceID] = arg
	return nil
}

func (m *mockIngesterStore) ListAdvisoryRatings(_ context.Context, advisoryIDs []uuid.UUID) ([]dbgen.ListAdvisoryRatingsRow, error) {
	state := m.state()
	var rows []dbgen.ListAdvisoryRatingsRow
	for _, advisoryID := range advisoryIDs {
		for _, source := range state.sources[advisoryID] {
			params := state.ratings[source.ID]
			for i, rater := range params.Raters {
				row := dbgen.ListAdvisoryRatingsRow{AdvisoryID: advisoryID, Provider: source.Provider, Rater: rater, CvssVector: params.Vectors[i]}
				if params.Versions[i] != "" {
					row.CvssVersion = dbgen.NullCvssVersion{CvssVersion: dbgen.CvssVersion(params.Versions[i]), Valid: true}
				}
				if params.Scores[i] != "" {
					row.CvssScore = sql.NullString{String: params.Scores[i], Valid: true}
				}
				if params.Labels[i] != "" {
					row.Label = dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevel(params.Labels[i]), Valid: true}
				}
				rows = append(rows, row)
			}
		}
	}
	return rows, nil
}

func (m *mockIngesterStore) SetAdvisoryRating(_ context.Context, arg dbgen.SetAdvisoryRatingParams) (dbgen.Advisory, error) {
	state := m.state()
	current := state.advisories[arg.AdvisoryID]
	current.Severity = arg.Severity
	current.CvssScore = arg.CvssScore
	current.CvssVersion = arg.CvssVersion
	current.CvssVector = arg.CvssVector
	current.RatedBy = arg.RatedBy
	state.advisories[arg.AdvisoryID] = current
	return current, nil
}

func (m *mockIngesterStore) ListFindingsForRating(context.Context, []uuid.UUID) ([]dbgen.ListFindingsForRatingRow, error) {
	return nil, nil
}

func (m *mockIngesterStore) SetFindingRating(context.Context, dbgen.SetFindingRatingParams) error {
	return nil
}

func (m *mockIngesterStore) ListCVERatingsForAdvisory(context.Context, uuid.UUID) ([]dbgen.ListCVERatingsForAdvisoryRow, error) {
	return nil, nil
}

func (m *mockIngesterStore) UpsertCVEAdvisorySource(context.Context, dbgen.UpsertCVEAdvisorySourceParams) (uuid.UUID, error) {
	return uuid.New(), nil
}

func (m *mockIngesterStore) DeleteCVEAdvisorySource(context.Context, uuid.UUID) error {
	return nil
}

func (m *mockIngesterStore) AddAdvisoryCWEs(_ context.Context, advisoryID uuid.UUID, ids []int) error {
	state := m.state()
	for _, id := range ids {
		if !slices.Contains(state.cwes[advisoryID], id) {
			state.cwes[advisoryID] = append(state.cwes[advisoryID], id)
		}
	}
	return nil
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
		ratings:      state.ratings,
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

func (m *mockIngesterStore) UpsertAdvisorySource(_ context.Context, arg dbgen.UpsertAdvisorySourceParams) (uuid.UUID, error) {
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
	current.RawData = arg.RawData
	current.FetchedAt = arg.FetchedAt
	m.sources[arg.AdvisoryID][arg.Provider] = current
	return current.ID, nil
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
	publishedAt := time.Now().UTC().Truncate(time.Second)

	ids, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID:  "GHSA-1111",
		Aliases:     []string{"CVE-2026-1111", "GHSA-1111"},
		Title:       "leftpad advisory",
		Description: "desc",
		// A vector OSV sends with no score: hibou computes 7.4 itself.
		Ratings:     []Rating{mustRating(t, "ghsa", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", nil)},
		CWEIDs:      []string{"CWE-79", "NVD-CWE-noinfo"},
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
	if !stored.CvssScore.Valid || stored.CvssScore.String != "7.4" || stored.RatedBy != "ghsa" {
		t.Fatalf("expected computed cvss score 7.4 rated by ghsa, got %#v by %q", stored.CvssScore, stored.RatedBy)
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
	// ADR-037: normalized to integers; NVD's "no mapping" placeholder dropped.
	if got := store.cwes[advisoryID]; !slices.Equal(got, []int{79}) {
		t.Fatalf("expected advisory CWEs [79], got %v", got)
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
	githubSource := uuid.New()
	store.sources[existingID] = map[string]dbgen.AdvisorySource{
		"github": {ID: githubSource, AdvisoryID: existingID, Provider: "github", ProviderID: "GHSA-existing"},
	}
	store.ratings[githubSource] = ratingsParams(githubSource, []Rating{mustRating(t, "ghsa", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", nil)})

	ingester := NewIngester(store, zerolog.Nop())
	ids, err := ingester.Ingest(context.Background(), "nvd", []IngestResult{{
		ProviderID: "CVE-2026-2222",
		Aliases:    []string{"GHSA-existing", "CVE-2026-2222"},
		Title:      "updated",
		Ratings:    []Rating{mustRating(t, "nvd", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil)},
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

// The exact cross-datasource shape in production: Trivy reports the bare CVE
// with no aliases, OSV later reports the GHSA whose alias list carries the
// same CVE. Both must land on one advisory with one source row per provider.
func TestIngesterReconcilesTrivyAndOSVSources(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())

	trivyIDs, err := ingester.Ingest(context.Background(), "trivy", []IngestResult{{
		ProviderID: "CVE-2019-10744",
		Title:      "lodash prototype pollution",
	}})
	if err != nil {
		t.Fatalf("trivy ingest: %v", err)
	}

	osvIDs, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID: "GHSA-jf85-cpcp-j695",
		Aliases:    []string{"CVE-2019-10744"},
		Title:      "Prototype Pollution in lodash",
	}})
	if err != nil {
		t.Fatalf("osv ingest: %v", err)
	}

	trivyID := trivyIDs["CVE-2019-10744"]
	osvID := osvIDs["GHSA-jf85-cpcp-j695"]
	if trivyID != osvID {
		t.Fatalf("expected one advisory, got trivy=%s osv=%s", trivyID, osvID)
	}
	if got := store.advisories[trivyID].CanonicalID; got != "CVE-2019-10744" {
		t.Fatalf("canonical = %q, want the CVE", got)
	}
	sources := store.sources[trivyID]
	if _, ok := sources["trivy"]; !ok {
		t.Fatal("missing trivy source row")
	}
	if _, ok := sources["osv"]; !ok {
		t.Fatal("missing osv source row")
	}
}

// OSV MAL-* records carry no CVSS and no database_specific.severity, so
// rating alone would file malicious packages as unknown. The floor pins every
// malware advisory to critical.
func TestMalwareSeverityFloor(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())
	ids, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{ProviderID: "MAL-2025-1", IsMalware: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.advisories[ids["MAL-2025-1"]].Severity; got != dbgen.SeverityLevelCritical {
		t.Fatalf("malware severity = %q, want critical", got)
	}
	ids, err = ingester.Ingest(context.Background(), "osv", []IngestResult{{ProviderID: "GO-2025-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.advisories[ids["GO-2025-1"]].Severity; got != dbgen.SeverityLevelUnknown {
		t.Fatalf("unrated severity = %q, want unknown (ADR-038 §3)", got)
	}
}

func mustRating(t *testing.T, rater, vector string, label *Severity) Rating {
	t.Helper()
	rating, ok := NewRating(rater, vector, nil, label)
	if !ok {
		t.Fatalf("rating %s %s rejected", rater, vector)
	}
	return rating
}

// ADR-028's dedup guarantee, exercised end to end rather than asserted.
//
// A human-authored mapping is written through this same ingest path under a
// "triage:*" source. If it minted a parallel identity, an org would carry two
// advisories for one vulnerability and double-count the moment upstream
// published coordinates. Carrying the CVE in Aliases is what prevents that:
// both results converge on one advisory row, with the CVE canonical and each
// source recorded separately.
func TestIngesterConvergesAuthoredAdvisoryOntoUpstream(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())
	ctx := context.Background()

	// Upstream arrives first, under its own GHSA identity.
	upstreamIDs, err := ingester.Ingest(ctx, "osv", []IngestResult{{
		ProviderID: "GHSA-cwxf-7cw2-7r32",
		Aliases:    []string{"CVE-2026-59084"},
		Title:      "Apache Tomcat",
		AffectedRanges: []AffectedRange{{
			Ecosystem:   "maven",
			PackageName: "org.apache.tomcat:tomcat-catalina",
			Introduced:  "11.0.0-M1",
			Fixed:       "11.0.24",
			Source:      "osv",
		}},
	}})
	if err != nil {
		t.Fatalf("upstream ingest: %v", err)
	}
	upstreamAdvisoryID := upstreamIDs["GHSA-cwxf-7cw2-7r32"]

	// A triager then authors coordinates for the same CVE.
	authoredIDs, err := ingester.Ingest(ctx, "triage:instance", []IngestResult{{
		ProviderID: "CVE-2026-59084",
		Aliases:    []string{"CVE-2026-59084"},
		Title:      "Apache Tomcat",
		AffectedRanges: []AffectedRange{{
			Ecosystem:    "maven",
			PackageName:  "org.apache.tomcat:tomcat-catalina",
			Introduced:   "11.0.0-M1",
			LastAffected: "11.0.23",
			Source:       "triage:instance",
		}},
	}})
	if err != nil {
		t.Fatalf("authored ingest: %v", err)
	}
	authoredAdvisoryID := authoredIDs["CVE-2026-59084"]

	if authoredAdvisoryID != upstreamAdvisoryID {
		t.Fatalf("authored data created a second advisory (%s) instead of joining %s",
			authoredAdvisoryID, upstreamAdvisoryID)
	}
	if stored := store.advisories[upstreamAdvisoryID]; stored.CanonicalID != "CVE-2026-59084" {
		t.Fatalf("canonical ID = %q, want the CVE", stored.CanonicalID)
	}
	// Both sources are recorded against the one advisory, so provenance survives.
	sources := store.sources[upstreamAdvisoryID]
	if _, ok := sources["osv"]; !ok {
		t.Error("upstream source was lost")
	}
	if _, ok := sources["triage:instance"]; !ok {
		t.Error("authored source was not recorded")
	}
}

// The reverse order matters just as much: a triager can author coordinates
// before any upstream database has them — that is the entire point — and
// upstream arriving later must join, not fork.
func TestIngesterConvergesUpstreamOntoAuthoredAdvisory(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())
	ctx := context.Background()

	authoredIDs, err := ingester.Ingest(ctx, "triage:instance", []IngestResult{{
		ProviderID: "CVE-2026-59084",
		Aliases:    []string{"CVE-2026-59084"},
		AffectedRanges: []AffectedRange{{
			Ecosystem:    "maven",
			PackageName:  "org.apache.tomcat:tomcat-catalina",
			LastAffected: "11.0.23",
			Source:       "triage:instance",
		}},
	}})
	if err != nil {
		t.Fatalf("authored ingest: %v", err)
	}

	upstreamIDs, err := ingester.Ingest(ctx, "osv", []IngestResult{{
		ProviderID: "GHSA-cwxf-7cw2-7r32",
		Aliases:    []string{"CVE-2026-59084"},
		AffectedRanges: []AffectedRange{{
			Ecosystem:   "maven",
			PackageName: "org.apache.tomcat:tomcat-catalina",
			Fixed:       "11.0.24",
			Source:      "osv",
		}},
	}})
	if err != nil {
		t.Fatalf("upstream ingest: %v", err)
	}

	if upstreamIDs["GHSA-cwxf-7cw2-7r32"] != authoredIDs["CVE-2026-59084"] {
		t.Fatal("upstream forked a second advisory instead of joining the authored one")
	}
}

// hibou's own identifier namespace is reserved but not yet issued, and it is
// closed to providers from the start.
//
// The risk is not that a provider names one by accident; it is that anything
// able to publish an advisory could join it to an identifier we intend to make
// authoritative later. Discovered after minting begins, those rows would be
// indistinguishable from real ones — so the namespace is closed before the
// first one is issued rather than after.
func TestIngesterRejectsReservedAliasesFromProviders(t *testing.T) {
	store := newMockIngesterStore()
	ingester := NewIngester(store, zerolog.Nop())

	ids, err := ingester.Ingest(context.Background(), "osv", []IngestResult{{
		ProviderID: "GHSA-aaaa-bbbb-cccc",
		Aliases:    []string{"CVE-2026-9999", "HSA-2026-0001"},
		Title:      "an advisory claiming a reserved identifier",
		AffectedRanges: []AffectedRange{{
			Ecosystem: "npm", PackageName: "leftpad", Fixed: "1.0.1",
		}},
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	advisoryID := ids["GHSA-aaaa-bbbb-cccc"]

	if _, claimed := store.aliases["HSA-2026-0001"]; claimed {
		t.Error("a provider claimed an identifier in hibou's reserved namespace")
	}
	// The rest of the record is still ingested: one stray alias must not block
	// a feed.
	if store.aliases["CVE-2026-9999"] != advisoryID {
		t.Error("rejecting a reserved alias dropped the legitimate ones too")
	}
	if store.advisories[advisoryID].CanonicalID != "CVE-2026-9999" {
		t.Errorf("canonical ID = %q", store.advisories[advisoryID].CanonicalID)
	}
}

func TestIsReservedIdentifier(t *testing.T) {
	for _, reserved := range []string{
		"HSA-2026-0001", "hsa-2026-1", "  HSA-1999-12345  ",
		// An instance's own namespace is reserved for the same reason ours is:
		// whoever mints it, nothing arriving from a provider may claim it.
		"HSAT-2026-0001", "hsat-2026-7",
	} {
		if !IsReservedIdentifier(reserved) {
			t.Errorf("IsReservedIdentifier(%q) = false", reserved)
		}
	}
	// Shape, not merely prefix: an unrelated vendor id is not ours to claim.
	for _, other := range []string{
		"", "CVE-2026-59084", "GHSA-cwxf-7cw2-7r32",
		"HSA", "HSA-", "HSAT", "HSA-CORP-2026-1", "HSATX-2026-1",
	} {
		if IsReservedIdentifier(other) {
			t.Errorf("IsReservedIdentifier(%q) = true, claiming an identifier that is not ours", other)
		}
	}
}
