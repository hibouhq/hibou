package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type mockCacheStore struct {
	entries             map[cacheKey]dbgen.AdvisoryCache
	packageInvalidation []dbgen.InvalidateAdvisoryCacheByPackageParams
	providerInvalidated []string
	upserts             []dbgen.UpsertAdvisoryCacheParams
}

func newMockCacheStore() *mockCacheStore {
	return &mockCacheStore{entries: map[cacheKey]dbgen.AdvisoryCache{}}
}

func (m *mockCacheStore) GetAdvisoryCache(_ context.Context, arg dbgen.GetAdvisoryCacheParams) (dbgen.AdvisoryCache, error) {
	entry, ok := m.entries[cacheKey{Ecosystem: arg.Ecosystem, Name: arg.PackageName}]
	if !ok || entry.Provider != arg.Provider || !entry.ExpiresAt.After(time.Now()) {
		return dbgen.AdvisoryCache{}, sql.ErrNoRows
	}
	return entry, nil
}

func (m *mockCacheStore) UpsertAdvisoryCache(_ context.Context, arg dbgen.UpsertAdvisoryCacheParams) error {
	m.upserts = append(m.upserts, arg)
	m.entries[cacheKey{Ecosystem: arg.Ecosystem, Name: arg.PackageName}] = dbgen.AdvisoryCache{
		ID:            uuid.New(),
		Ecosystem:     arg.Ecosystem,
		PackageName:   arg.PackageName,
		Provider:      arg.Provider,
		ResponseData:  arg.ResponseData,
		AdvisoryCount: arg.AdvisoryCount,
		FetchedAt:     arg.FetchedAt,
		ExpiresAt:     arg.ExpiresAt,
	}
	return nil
}

func (m *mockCacheStore) InvalidateAdvisoryCacheByPackage(_ context.Context, arg dbgen.InvalidateAdvisoryCacheByPackageParams) error {
	m.packageInvalidation = append(m.packageInvalidation, arg)
	delete(m.entries, cacheKey{Ecosystem: arg.Ecosystem, Name: arg.PackageName})
	return nil
}

func (m *mockCacheStore) InvalidateAdvisoryCacheByProvider(_ context.Context, provider string) error {
	m.providerInvalidated = append(m.providerInvalidated, provider)
	for key, entry := range m.entries {
		if entry.Provider == provider {
			delete(m.entries, key)
		}
	}
	return nil
}

type mockProvider struct {
	name      string
	batchSize int
	results   map[cacheKey][]provider.AdvisoryResult
	calls     [][]provider.PackageQuery
}

func (m *mockProvider) Name() string { return m.name }

func (m *mockProvider) SupportedEcosystems() []string { return []string{"npm", "pypi"} }

func (m *mockProvider) BatchSize() int { return m.batchSize }

func (m *mockProvider) QueryPackages(_ context.Context, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	m.calls = append(m.calls, append([]provider.PackageQuery(nil), queries...))
	results := make([]provider.AdvisoryResult, 0)
	for _, query := range queries {
		results = append(results, m.results[cacheKey{Ecosystem: query.Ecosystem, Name: query.Name}]...)
	}
	return results, nil
}

func TestDedupeQueries(t *testing.T) {
	// The advisory cache is package-level by design, so duplicate package queries
	// collapse even when callers provide different versions.
	queries := dedupeQueries([]provider.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}, {Ecosystem: "NPM", Name: "left-pad", Version: "1.0.1"}, {Ecosystem: "pypi", Name: "django", Version: "3.2.1"}})
	if len(queries) != 2 {
		t.Fatalf("expected 2 deduped queries, got %d", len(queries))
	}
	if queries[0].Ecosystem != "npm" {
		t.Fatalf("expected normalized ecosystem, got %s", queries[0].Ecosystem)
	}
}

func TestChunkQueries(t *testing.T) {
	queries := []provider.PackageQuery{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	chunks := chunkQueries(queries, 2)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 2 || len(chunks[1]) != 1 {
		t.Fatalf("unexpected chunk sizes: %#v", chunks)
	}
}

func TestQueryWithCacheUsesHitsAndCachesMisses(t *testing.T) {
	store := newMockCacheStore()
	cachedPayload, err := json.Marshal([]provider.AdvisoryResult{{ProviderName: "osv", ProviderID: "cached-1"}})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	store.entries[cacheKey{Ecosystem: "npm", Name: "left-pad"}] = dbgen.AdvisoryCache{
		ID:           uuid.New(),
		Ecosystem:    "npm",
		PackageName:  "left-pad",
		Provider:     "osv",
		ResponseData: cachedPayload,
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	prov := &mockProvider{
		name:      "osv",
		batchSize: 1,
		results: map[cacheKey][]provider.AdvisoryResult{
			{Ecosystem: "npm", Name: "lodash"}: {{
				ProviderName: "osv",
				ProviderID:   "fresh-1",
				AffectedRanges: []advisory.AffectedRange{{
					Ecosystem:   "npm",
					PackageName: "lodash",
				}},
			}},
			{Ecosystem: "pypi", Name: "django"}: {{
				ProviderName: "osv",
				ProviderID:   "fresh-2",
				AffectedRanges: []advisory.AffectedRange{{
					Ecosystem:   "pypi",
					PackageName: "django",
				}},
			}},
		},
	}

	svc := &Service{
		cache: store,
		config: Config{
			DefaultTTL: time.Hour,
		},
		log: zerolog.Nop(),
	}

	results, err := svc.QueryWithCache(context.Background(), prov, []provider.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}, {Ecosystem: "npm", Name: "left-pad", Version: "1.0.1"}, {Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}, {Ecosystem: "pypi", Name: "django", Version: "3.2.1"}})
	if err != nil {
		t.Fatalf("QueryWithCache() error = %v", err)
	}
	if len(prov.calls) != 2 {
		t.Fatalf("expected 2 provider calls due to chunking, got %d", len(prov.calls))
	}
	if len(store.upserts) != 2 {
		t.Fatalf("expected 2 cache upserts, got %d", len(store.upserts))
	}
	gotIDs := []string{results[0].ProviderID, results[1].ProviderID, results[2].ProviderID}
	if !reflect.DeepEqual(gotIDs, []string{"cached-1", "fresh-1", "fresh-2"}) {
		t.Fatalf("unexpected results: %#v", gotIDs)
	}
}

func TestQueryWithCacheReusesPackageCacheAcrossVersions(t *testing.T) {
	store := newMockCacheStore()
	prov := &mockProvider{
		name:      "osv",
		batchSize: 10,
		results: map[cacheKey][]provider.AdvisoryResult{
			{Ecosystem: "npm", Name: "left-pad"}: {{
				ProviderName: "osv",
				ProviderID:   "pkg-advisory",
				AffectedRanges: []advisory.AffectedRange{{
					Ecosystem:   "npm",
					PackageName: "left-pad",
				}},
			}},
		},
	}

	svc := &Service{
		cache: store,
		config: Config{
			DefaultTTL: time.Hour,
		},
		log: zerolog.Nop(),
	}

	firstResults, err := svc.QueryWithCache(context.Background(), prov, []provider.PackageQuery{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.0",
	}})
	if err != nil {
		t.Fatalf("first QueryWithCache() error = %v", err)
	}
	if len(firstResults) != 1 {
		t.Fatalf("expected first query to return 1 result, got %d", len(firstResults))
	}

	secondResults, err := svc.QueryWithCache(context.Background(), prov, []provider.PackageQuery{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.1",
	}})
	if err != nil {
		t.Fatalf("second QueryWithCache() error = %v", err)
	}
	if len(secondResults) != 1 {
		t.Fatalf("expected second query to return 1 result, got %d", len(secondResults))
	}
	if len(prov.calls) != 1 {
		t.Fatalf("expected provider to be called once across versions, got %d", len(prov.calls))
	}
	if len(store.upserts) != 1 {
		t.Fatalf("expected one cache upsert, got %d", len(store.upserts))
	}
}

func TestInvalidateHelpers(t *testing.T) {
	store := newMockCacheStore()
	svc := &Service{cache: store, config: Config{DefaultTTL: time.Hour}, log: zerolog.Nop()}

	if err := svc.InvalidateByPackage(context.Background(), "npm", "left-pad"); err != nil {
		t.Fatalf("InvalidateByPackage() error = %v", err)
	}
	if err := svc.InvalidateByProvider(context.Background(), "osv"); err != nil {
		t.Fatalf("InvalidateByProvider() error = %v", err)
	}
	if len(store.packageInvalidation) != 1 || len(store.providerInvalidated) != 1 {
		t.Fatalf("expected invalidations to be recorded")
	}
}
