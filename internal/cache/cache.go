package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/metrics"
	"github.com/hibouhq/lehibou/internal/provider"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Config struct {
	DefaultTTL   time.Duration
	ProviderTTLs map[string]time.Duration
}

type advisoryCacheStore interface {
	GetAdvisoryCache(ctx context.Context, arg dbgen.GetAdvisoryCacheParams) (dbgen.AdvisoryCache, error)
	UpsertAdvisoryCache(ctx context.Context, arg dbgen.UpsertAdvisoryCacheParams) error
	InvalidateAdvisoryCacheByPackage(ctx context.Context, arg dbgen.InvalidateAdvisoryCacheByPackageParams) error
	InvalidateAdvisoryCacheByProvider(ctx context.Context, provider string) error
}

type Service struct {
	queries *store.Queries
	cache   advisoryCacheStore
	config  Config
	log     zerolog.Logger
}

type cacheKey struct {
	Ecosystem string
	Name      string
}

func New(queries *store.Queries, cfg Config, log zerolog.Logger) *Service {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 6 * time.Hour
	}
	if cfg.ProviderTTLs == nil {
		cfg.ProviderTTLs = map[string]time.Duration{}
	}

	return &Service{
		queries: queries,
		cache:   queries,
		config:  cfg,
		log:     log,
	}
}

// QueryWithCache caches advisories per package/provider. Version from PackageQuery is
// not used for caching. All advisories for a package are fetched and cached, and
// version matching happens downstream.
func (s *Service) QueryWithCache(ctx context.Context, prov provider.AdvisoryProvider, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	providerName := prov.Name()
	uniqueQueries := dedupeQueries(queries)
	hitResults := make([]provider.AdvisoryResult, 0)
	missQueries := make([]provider.PackageQuery, 0)

	for _, query := range uniqueQueries {
		cached, err := s.cache.GetAdvisoryCache(ctx, dbgen.GetAdvisoryCacheParams{
			Ecosystem:   query.Ecosystem,
			PackageName: query.Name,
			Provider:    providerName,
		})
		if err == nil {
			var cachedResults []provider.AdvisoryResult
			if err := json.Unmarshal(cached.ResponseData, &cachedResults); err != nil {
				return nil, fmt.Errorf("cache: unmarshal advisory cache for %s/%s: %w", query.Ecosystem, query.Name, err)
			}
			metrics.CacheHits.WithLabelValues(providerName).Inc()
			hitResults = append(hitResults, cachedResults...)
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("cache: get advisory cache for %s/%s: %w", query.Ecosystem, query.Name, err)
		}
		metrics.CacheMisses.WithLabelValues(providerName).Inc()
		missQueries = append(missQueries, query)
	}

	freshResults := make([]provider.AdvisoryResult, 0)
	for _, chunk := range chunkQueries(missQueries, prov.BatchSize()) {
		batchResults, err := prov.QueryPackages(ctx, chunk)
		if err != nil {
			return nil, fmt.Errorf("cache: query provider %s: %w", providerName, err)
		}

		for _, query := range chunk {
			matched := filterResultsForQuery(query, batchResults)
			payload, err := json.Marshal(matched)
			if err != nil {
				return nil, fmt.Errorf("cache: marshal advisory cache for %s/%s: %w", query.Ecosystem, query.Name, err)
			}
			fetchedAt := time.Now().UTC()
			if err := s.cache.UpsertAdvisoryCache(ctx, dbgen.UpsertAdvisoryCacheParams{
				Ecosystem:     query.Ecosystem,
				PackageName:   query.Name,
				Provider:      providerName,
				ResponseData:  payload,
				AdvisoryCount: int32(len(matched)),
				FetchedAt:     fetchedAt,
				ExpiresAt:     fetchedAt.Add(s.ttlForProvider(providerName)),
			}); err != nil {
				return nil, fmt.Errorf("cache: upsert advisory cache for %s/%s: %w", query.Ecosystem, query.Name, err)
			}
			freshResults = append(freshResults, matched...)
		}
	}

	return append(hitResults, freshResults...), nil
}

func (s *Service) InvalidateByPackage(ctx context.Context, ecosystem, packageName string) error {
	if err := s.cache.InvalidateAdvisoryCacheByPackage(ctx, dbgen.InvalidateAdvisoryCacheByPackageParams{
		Ecosystem:   ecosystem,
		PackageName: packageName,
	}); err != nil {
		return fmt.Errorf("cache: invalidate package %s/%s: %w", ecosystem, packageName, err)
	}
	return nil
}

func (s *Service) InvalidateByProvider(ctx context.Context, providerName string) error {
	if err := s.cache.InvalidateAdvisoryCacheByProvider(ctx, providerName); err != nil {
		return fmt.Errorf("cache: invalidate provider %s: %w", providerName, err)
	}
	return nil
}

func (s *Service) ttlForProvider(providerName string) time.Duration {
	if ttl, ok := s.config.ProviderTTLs[strings.ToLower(providerName)]; ok && ttl > 0 {
		return ttl
	}
	if ttl, ok := s.config.ProviderTTLs[providerName]; ok && ttl > 0 {
		return ttl
	}
	return s.config.DefaultTTL
}

func dedupeQueries(queries []provider.PackageQuery) []provider.PackageQuery {
	// Version is intentionally excluded because advisories are cached per-package,
	// not per-version.
	seen := make(map[cacheKey]struct{}, len(queries))
	unique := make([]provider.PackageQuery, 0, len(queries))
	for _, query := range queries {
		key := cacheKey{Ecosystem: strings.ToLower(strings.TrimSpace(query.Ecosystem)), Name: query.Name}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		query.Ecosystem = key.Ecosystem
		unique = append(unique, query)
	}
	return unique
}

func chunkQueries(queries []provider.PackageQuery, batchSize int) [][]provider.PackageQuery {
	if len(queries) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = len(queries)
	}

	chunks := make([][]provider.PackageQuery, 0, (len(queries)+batchSize-1)/batchSize)
	for start := 0; start < len(queries); start += batchSize {
		end := start + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		chunks = append(chunks, queries[start:end])
	}
	return chunks
}

func filterResultsForQuery(query provider.PackageQuery, results []provider.AdvisoryResult) []provider.AdvisoryResult {
	matched := make([]provider.AdvisoryResult, 0)
	for _, result := range results {
		if resultMatchesQuery(query, result) {
			matched = append(matched, result)
		}
	}
	return matched
}

func resultMatchesQuery(query provider.PackageQuery, result provider.AdvisoryResult) bool {
	for _, affected := range result.AffectedRanges {
		if strings.EqualFold(affected.Ecosystem, query.Ecosystem) && affected.PackageName == query.Name {
			return true
		}
	}
	return false
}
