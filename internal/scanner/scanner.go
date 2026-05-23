package scanner

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/advisory"
	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/cache"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/provider"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
	"github.com/hibouhq/lehibou/internal/versioncmp"
)

type queryStore interface {
	ListComponentsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error)
	CreateScan(ctx context.Context, arg dbgen.CreateScanParams) (dbgen.Scan, error)
	UpdateScanStatus(ctx context.Context, arg dbgen.UpdateScanStatusParams) (dbgen.Scan, error)
	CreateScanProvider(ctx context.Context, arg dbgen.CreateScanProviderParams) (dbgen.ScanProvider, error)
	UpdateScanProvider(ctx context.Context, arg dbgen.UpdateScanProviderParams) (dbgen.ScanProvider, error)
	ListAffectedRangesByPackage(ctx context.Context, arg dbgen.ListAffectedRangesByPackageParams) ([]dbgen.AffectedRange, error)
	UpsertVulnMatch(ctx context.Context, arg dbgen.UpsertVulnMatchParams) (dbgen.VulnMatch, error)
	MarkStaleVulnMatches(ctx context.Context, arg dbgen.MarkStaleVulnMatchesParams) error
	CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error)
}

type cacheClient interface {
	QueryWithCache(ctx context.Context, prov provider.AdvisoryProvider, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error)
	InvalidateByPackage(ctx context.Context, ecosystem, packageName string) error
}

type advisoryIngester interface {
	Ingest(ctx context.Context, providerName string, results []advisory.IngestResult) (map[string]uuid.UUID, error)
}

type eventPublisher interface {
	Publish(ctx context.Context, evt events.Event)
}

type Service struct {
	queries   queryStore
	cache     cacheClient
	ingester  advisoryIngester
	bus       eventPublisher
	providers map[string]provider.AdvisoryProvider
	log       zerolog.Logger
}

func New(queries queryStore, cache cacheClient, ingester advisoryIngester, bus eventPublisher, providers map[string]provider.AdvisoryProvider, log zerolog.Logger) *Service {
	if providers == nil {
		providers = map[string]provider.AdvisoryProvider{}
	}
	return &Service{
		queries:   queries,
		cache:     cache,
		ingester:  ingester,
		bus:       bus,
		providers: providers,
		log:       log.With().Str("component", "scanner.service").Logger(),
	}
}

var (
	_ queryStore       = (*store.Queries)(nil)
	_ cacheClient      = (*cache.Service)(nil)
	_ advisoryIngester = (*advisory.Ingester)(nil)
	_ eventPublisher   = (*events.Bus)(nil)
)

func (s *Service) RunScan(ctx context.Context, snapshotID uuid.UUID, providerNames []string, triggeredBy string) (uuid.UUID, error) {
	resolvedProviders := s.resolveProviders(providerNames)
	scanRecord, err := s.queries.CreateScan(ctx, dbgen.CreateScanParams{
		SnapshotID:         snapshotID,
		Status:             "pending",
		ProvidersRequested: resolvedProviders,
		TriggeredBy:        normalizeTriggeredBy(triggeredBy),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create scan: %w", err)
	}

	startedAt := time.Now().UTC()
	if _, err := s.queries.UpdateScanStatus(ctx, dbgen.UpdateScanStatusParams{
		ID:        scanRecord.ID,
		Status:    "running",
		StartedAt: sql.NullTime{Time: startedAt, Valid: true},
	}); err != nil {
		return scanRecord.ID, fmt.Errorf("mark scan running: %w", err)
	}

	components, err := s.queries.ListComponentsBySnapshot(ctx, snapshotID)
	if err != nil {
		return scanRecord.ID, s.failScan(ctx, scanRecord.ID, snapshotID, fmt.Errorf("list components: %w", err))
	}

	packageQueries := buildPackageQueries(components)
	providerSucceeded := 0
	providerFailed := 0
	freshMatchIDs := make(map[uuid.UUID]struct{})

	for _, providerName := range resolvedProviders {
		providerRecord, providerErr := s.queries.CreateScanProvider(ctx, dbgen.CreateScanProviderParams{
			ScanID:   scanRecord.ID,
			Provider: providerName,
			Status:   "running",
		})
		if providerErr != nil {
			providerFailed++
			s.log.Error().Err(providerErr).Str("provider", providerName).Msg("create scan provider record")
			continue
		}

		providerStart := time.Now().UTC()
		prov, ok := s.providers[providerName]
		if !ok {
			providerFailed++
			s.log.Error().Str("provider", providerName).Msg("provider not configured")
			s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), 0, "failed", "provider not configured")
			continue
		}

		results, err := s.cache.QueryWithCache(ctx, prov, packageQueries)
		if err != nil {
			providerFailed++
			s.log.Error().Err(err).Str("provider", providerName).Msg("query advisories")
			s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), 0, "failed", err.Error())
			continue
		}

		advisoryMap, err := s.ingester.Ingest(ctx, providerName, toIngestResults(results))
		if err != nil {
			providerFailed++
			s.log.Error().Err(err).Str("provider", providerName).Msg("ingest advisories")
			s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), int32(len(results)), "failed", err.Error())
			continue
		}

		providerMatchIDs, err := s.matchComponents(ctx, snapshotID, components, advisoryMap)
		if err != nil {
			providerFailed++
			s.log.Error().Err(err).Str("provider", providerName).Msg("match affected ranges")
			s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), int32(len(advisoryMap)), "failed", err.Error())
			continue
		}
		for _, matchID := range providerMatchIDs {
			freshMatchIDs[matchID] = struct{}{}
		}

		providerSucceeded++
		s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), int32(len(advisoryMap)), "complete", "")
	}

	completedAt := time.Now().UTC()
	finalStatus := "complete"
	errorMessage := ""
	eventType := events.ScanCompleted
	if len(resolvedProviders) == 0 || providerSucceeded == 0 {
		finalStatus = "failed"
		eventType = events.ScanFailed
		errorMessage = "all providers failed"
	}

	if providerSucceeded > 0 {
		if err := s.queries.MarkStaleVulnMatches(ctx, dbgen.MarkStaleVulnMatchesParams{
			SnapshotID:    snapshotID,
			FreshMatchIds: uniqueMatchIDs(freshMatchIDs),
		}); err != nil {
			return scanRecord.ID, s.failScan(ctx, scanRecord.ID, snapshotID, fmt.Errorf("mark stale vuln matches: %w", err))
		}
	}

	if _, err := s.queries.UpdateScanStatus(ctx, dbgen.UpdateScanStatusParams{
		ID:           scanRecord.ID,
		Status:       finalStatus,
		ErrorMessage: errorMessage,
		StartedAt:    sql.NullTime{Time: startedAt, Valid: true},
		CompletedAt:  sql.NullTime{Time: completedAt, Valid: true},
	}); err != nil {
		return scanRecord.ID, fmt.Errorf("update scan status: %w", err)
	}

	s.publish(ctx, eventType, map[string]any{
		"scan_id":          scanRecord.ID.String(),
		"snapshot_id":      snapshotID.String(),
		"providers":        resolvedProviders,
		"providers_failed": providerFailed,
	})

	if finalStatus == "failed" {
		return scanRecord.ID, errors.New(errorMessage)
	}
	return scanRecord.ID, nil
}

func (s *Service) TriggerRescan(ctx context.Context, snapshotID uuid.UUID, providerNames []string, actor audit.Entry) (uuid.UUID, error) {
	components, err := s.queries.ListComponentsBySnapshot(ctx, snapshotID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("list components for rescan: %w", err)
	}

	for _, pkg := range buildPackageQueries(components) {
		if err := s.cache.InvalidateByPackage(ctx, pkg.Ecosystem, pkg.Name); err != nil {
			return uuid.Nil, fmt.Errorf("invalidate cache for %s/%s: %w", pkg.Ecosystem, pkg.Name, err)
		}
	}

	scanID, err := s.RunScan(ctx, snapshotID, providerNames, normalizeTriggeredBy(actor.ActorDisplay))
	if err != nil {
		return scanID, err
	}

	contextPayload, marshalErr := json.Marshal(map[string]any{
		"snapshot_id": snapshotID.String(),
		"providers":   s.resolveProviders(providerNames),
	})
	if marshalErr != nil {
		return scanID, fmt.Errorf("marshal audit context: %w", marshalErr)
	}

	if _, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorID:      toNullUUID(actor.ActorID),
		ActorType:    actor.ActorType,
		ActorDisplay: actor.ActorDisplay,
		Action:       audit.ActionScanTrigger,
		ResourceType: "scan",
		ResourceID:   scanID.String(),
		OrgID:        toNullUUID(actor.OrgID),
		Context:      contextPayload,
		IpAddress:    actor.IPAddress,
		UserAgent:    actor.UserAgent,
	}); err != nil {
		return scanID, fmt.Errorf("create audit log: %w", err)
	}

	return scanID, nil
}

func (s *Service) matchComponents(ctx context.Context, snapshotID uuid.UUID, components []dbgen.Component, advisoryMap map[string]uuid.UUID) ([]uuid.UUID, error) {
	if len(advisoryMap) == 0 || len(components) == 0 {
		return nil, nil
	}

	advisorySet := make(map[uuid.UUID]struct{}, len(advisoryMap))
	for _, advisoryID := range advisoryMap {
		advisorySet[advisoryID] = struct{}{}
	}

	rangeCache := make(map[string][]dbgen.AffectedRange)
	freshMatchIDs := make([]uuid.UUID, 0)
	for _, component := range components {
		cacheKey := packageKey(component.Ecosystem, component.Name)
		ranges, ok := rangeCache[cacheKey]
		if !ok {
			loaded, err := s.queries.ListAffectedRangesByPackage(ctx, dbgen.ListAffectedRangesByPackageParams{
				Ecosystem:   component.Ecosystem,
				PackageName: component.Name,
			})
			if err != nil {
				return nil, fmt.Errorf("list affected ranges for %s/%s: %w", component.Ecosystem, component.Name, err)
			}
			ranges = loaded
			rangeCache[cacheKey] = ranges
		}

		for _, affectedRange := range ranges {
			if _, ok := advisorySet[affectedRange.AdvisoryID]; !ok {
				continue
			}
			affected, err := versioncmp.InRange(component.Ecosystem, component.Version, affectedRange.Introduced, affectedRange.Fixed, affectedRange.LastAffected)
			if err != nil {
				s.log.Warn().
					Err(err).
					Str("ecosystem", component.Ecosystem).
					Str("component", component.Name).
					Msg("skip version match")
				continue
			}
			if !affected {
				continue
			}

			rangeID := uuid.NullUUID{UUID: affectedRange.ID, Valid: true}
			matchRecord, err := s.queries.UpsertVulnMatch(ctx, dbgen.UpsertVulnMatchParams{
				SnapshotID:      snapshotID,
				ComponentID:     component.ID,
				AdvisoryID:      affectedRange.AdvisoryID,
				AffectedRangeID: rangeID,
				IsAffected:      true,
			})
			if err != nil {
				return nil, fmt.Errorf("upsert vuln match for component %s advisory %s: %w", component.ID, affectedRange.AdvisoryID, err)
			}
			freshMatchIDs = append(freshMatchIDs, matchRecord.ID)
		}
	}

	return freshMatchIDs, nil
}

func (s *Service) failScan(ctx context.Context, scanID, snapshotID uuid.UUID, err error) error {
	completedAt := time.Now().UTC()
	if _, updateErr := s.queries.UpdateScanStatus(ctx, dbgen.UpdateScanStatusParams{
		ID:           scanID,
		Status:       "failed",
		ErrorMessage: err.Error(),
		CompletedAt:  sql.NullTime{Time: completedAt, Valid: true},
	}); updateErr != nil {
		return fmt.Errorf("%v; update scan failure: %w", err, updateErr)
	}
	s.publish(ctx, events.ScanFailed, map[string]any{
		"scan_id":     scanID.String(),
		"snapshot_id": snapshotID.String(),
		"error":       err.Error(),
	})
	return err
}

func (s *Service) completeProvider(ctx context.Context, providerRecord dbgen.ScanProvider, startedAt time.Time, cacheMisses, advisoriesFound int32, status, errorMessage string) {
	completedAt := time.Now().UTC()
	responseTime := int32(completedAt.Sub(startedAt) / time.Millisecond)
	if _, err := s.queries.UpdateScanProvider(ctx, dbgen.UpdateScanProviderParams{
		ID:              providerRecord.ID,
		Status:          status,
		CacheHits:       0,
		CacheMisses:     cacheMisses,
		AdvisoriesFound: advisoriesFound,
		ResponseTimeMs:  sql.NullInt32{Int32: responseTime, Valid: true},
		DbVersion:       "",
		ErrorMessage:    errorMessage,
		StartedAt:       sql.NullTime{Time: startedAt, Valid: true},
		CompletedAt:     sql.NullTime{Time: completedAt, Valid: true},
	}); err != nil {
		s.log.Error().Err(err).Str("provider", providerRecord.Provider).Msg("update scan provider")
	}
}

func (s *Service) resolveProviders(providerNames []string) []string {
	if len(providerNames) == 0 {
		resolved := make([]string, 0, len(s.providers))
		for name := range s.providers {
			resolved = append(resolved, name)
		}
		sort.Strings(resolved)
		return resolved
	}

	seen := make(map[string]struct{}, len(providerNames))
	resolved := make([]string, 0, len(providerNames))
	for _, name := range providerNames {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		resolved = append(resolved, trimmed)
	}
	return resolved
}

func (s *Service) publish(ctx context.Context, eventType events.Type, payload any) {
	if s.bus == nil {
		return
	}
	s.bus.Publish(ctx, events.Event{Type: eventType, Payload: payload, Timestamp: time.Now().UTC()})
}

func buildPackageQueries(components []dbgen.Component) []provider.PackageQuery {
	seen := make(map[string]struct{}, len(components))
	queries := make([]provider.PackageQuery, 0, len(components))
	for _, component := range components {
		key := component.Ecosystem + "\x00" + component.Name + "\x00" + component.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		queries = append(queries, provider.PackageQuery{
			Ecosystem: component.Ecosystem,
			Name:      component.Name,
			Version:   component.Version,
		})
	}
	return queries
}

func packageKey(ecosystem, name string) string {
	return ecosystem + "\x00" + name
}

func normalizeTriggeredBy(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return audit.ActorSystem
	}
	return trimmed
}

func toNullUUID(value *uuid.UUID) uuid.NullUUID {
	if value == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *value, Valid: true}
}

func toIngestResults(results []provider.AdvisoryResult) []advisory.IngestResult {
	converted := make([]advisory.IngestResult, 0, len(results))
	for _, result := range results {
		converted = append(converted, advisory.IngestResult{
			ProviderID:     result.ProviderID,
			Aliases:        append([]string(nil), result.Aliases...),
			Title:          result.Title,
			Description:    result.Description,
			Severity:       result.Severity,
			CVSSScore:      result.CVSSScore,
			CVSSVersion:    result.CVSSVersion,
			CVSSVector:     result.CVSSVector,
			CWEIDs:         append([]string(nil), result.CWEIDs...),
			IsMalware:      result.IsMalware,
			MalwareType:    result.MalwareType,
			AffectedRanges: append([]advisory.AffectedRange(nil), result.AffectedRanges...),
			PublishedAt:    result.PublishedAt,
			WithdrawnAt:    result.WithdrawnAt,
			RawData:        result.RawData,
		})
	}
	return converted
}

func uniqueMatchIDs(values map[uuid.UUID]struct{}) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	return ids
}
