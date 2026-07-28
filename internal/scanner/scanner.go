package scanner

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cache"
	"github.com/hibouhq/hibou/internal/distro"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/versioncmp"
)

type queryStore interface {
	ListComponentsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error)
	CreateScan(ctx context.Context, arg dbgen.CreateScanParams) (dbgen.Scan, error)
	UpdateScanStatus(ctx context.Context, arg dbgen.UpdateScanStatusParams) (dbgen.Scan, error)
	CreateScanProvider(ctx context.Context, arg dbgen.CreateScanProviderParams) (dbgen.ScanProvider, error)
	UpdateScanProvider(ctx context.Context, arg dbgen.UpdateScanProviderParams) (dbgen.ScanProvider, error)
	ListAffectedRangesByPackage(ctx context.Context, arg dbgen.ListAffectedRangesByPackageParams) ([]dbgen.AffectedRange, error)
	GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error)
	CreateVulnerability(ctx context.Context, params dbgen.CreateVulnerabilityParams) (*store.Vulnerability, error)
	MarkStaleVulnerabilities(ctx context.Context, snapshotID uuid.UUID, vulnType string, freshIDs []uuid.UUID) error
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

const providerNotConfiguredMessage = "provider not configured"

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
	scanRecord, startedAt, err := s.startScan(ctx, snapshotID, resolvedProviders, triggeredBy)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create scan: %w", err)
	}

	components, err := s.queries.ListComponentsBySnapshot(ctx, snapshotID)
	if err != nil {
		return scanRecord.ID, s.failScan(ctx, scanRecord.ID, snapshotID, fmt.Errorf("list components: %w", err))
	}

	packageQueries := buildPackageQueries(components)
	freshMatchIDsByType := map[string]map[uuid.UUID]struct{}{
		"dependency": {},
		"malware":    {},
	}

	providerSucceeded := 0
	providerFailed := 0
	for _, providerName := range resolvedProviders {
		providerResult, err := s.runScanProvider(ctx, scanRecord.ID, snapshotID, providerName, components, packageQueries)
		if err != nil {
			providerFailed++
			continue
		}
		mergeFreshMatchIDs(freshMatchIDsByType, providerResult.matchIDsByType)
		providerSucceeded++
	}
	return s.finalizeScan(ctx, scanCompletion{
		scanID:              scanRecord.ID,
		snapshotID:          snapshotID,
		resolvedProviders:   resolvedProviders,
		startedAt:           startedAt,
		providerSucceeded:   providerSucceeded,
		providerFailed:      providerFailed,
		freshMatchIDsByType: freshMatchIDsByType,
	})
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

func (s *Service) matchComponents(ctx context.Context, snapshotID uuid.UUID, providerName string, components []dbgen.Component, advisoryMap map[string]uuid.UUID) (map[string][]uuid.UUID, error) {
	if len(advisoryMap) == 0 || len(components) == 0 {
		return nil, nil
	}

	state := newComponentMatchState(advisoryMap)
	freshMatchIDs := map[string][]uuid.UUID{"dependency": {}, "malware": {}}
	for _, component := range components {
		if err := s.matchComponentRanges(ctx, snapshotID, providerName, component, state, freshMatchIDs); err != nil {
			return nil, err
		}
	}

	return freshMatchIDs, nil
}

type scanProviderResult struct {
	matchIDsByType map[string][]uuid.UUID
}

type scanCompletion struct {
	scanID              uuid.UUID
	snapshotID          uuid.UUID
	resolvedProviders   []string
	startedAt           time.Time
	providerSucceeded   int
	providerFailed      int
	freshMatchIDsByType map[string]map[uuid.UUID]struct{}
}

type componentMatchState struct {
	advisorySet   map[uuid.UUID]struct{}
	rangeCache    map[string][]dbgen.AffectedRange
	advisoryCache map[uuid.UUID]dbgen.Advisory
}

func (s *Service) startScan(ctx context.Context, snapshotID uuid.UUID, resolvedProviders []string, triggeredBy string) (dbgen.Scan, time.Time, error) {
	scanRecord, err := s.queries.CreateScan(ctx, dbgen.CreateScanParams{
		SnapshotID:         snapshotID,
		Status:             "pending",
		ProvidersRequested: resolvedProviders,
		TriggeredBy:        normalizeTriggeredBy(triggeredBy),
	})
	if err != nil {
		return dbgen.Scan{}, time.Time{}, err
	}
	startedAt := time.Now().UTC()
	if _, err := s.queries.UpdateScanStatus(ctx, dbgen.UpdateScanStatusParams{
		ID:        scanRecord.ID,
		Status:    "running",
		StartedAt: sql.NullTime{Time: startedAt, Valid: true},
	}); err != nil {
		return scanRecord, time.Time{}, fmt.Errorf("mark scan running: %w", err)
	}
	return scanRecord, startedAt, nil
}

func (s *Service) runScanProvider(ctx context.Context, scanID, snapshotID uuid.UUID, providerName string, components []dbgen.Component, packageQueries []provider.PackageQuery) (*scanProviderResult, error) {
	providerRecord, providerErr := s.queries.CreateScanProvider(ctx, dbgen.CreateScanProviderParams{
		ScanID:   scanID,
		Provider: providerName,
		Status:   "running",
	})
	if providerErr != nil {
		s.log.Error().Err(providerErr).Str("provider", providerName).Msg("create scan provider record")
		return nil, providerErr
	}

	providerStart := time.Now().UTC()
	prov, ok := s.providers[providerName]
	if !ok {
		s.log.Error().Str("provider", providerName).Msg(providerNotConfiguredMessage)
		s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), 0, "failed", providerNotConfiguredMessage) //nolint:gosec // G115: query counts are bounded by component batch size.
		return nil, errors.New(providerNotConfiguredMessage)
	}

	results, err := s.cache.QueryWithCache(ctx, prov, packageQueries)
	if err != nil {
		s.log.Error().Err(err).Str("provider", providerName).Msg("query advisories")
		s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), 0, "failed", err.Error()) //nolint:gosec // G115: query counts are bounded by component batch size.
		return nil, err
	}

	advisoryMap, err := s.ingester.Ingest(ctx, providerName, toIngestResults(results))
	if err != nil {
		s.log.Error().Err(err).Str("provider", providerName).Msg("ingest advisories")
		s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), int32(len(results)), "failed", err.Error()) //nolint:gosec // G115: provider result counts are bounded by requested packages.
		return nil, err
	}

	providerMatchIDsByType, err := s.matchComponents(ctx, snapshotID, providerName, components, advisoryMap)
	if err != nil {
		s.log.Error().Err(err).Str("provider", providerName).Msg("match affected ranges")
		s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), int32(len(advisoryMap)), "failed", err.Error()) //nolint:gosec // G115: advisory counts are bounded by provider responses.
		return nil, err
	}

	s.completeProvider(ctx, providerRecord, providerStart, int32(len(packageQueries)), int32(len(advisoryMap)), "complete", "") //nolint:gosec // G115: advisory counts are bounded by provider responses.
	return &scanProviderResult{matchIDsByType: providerMatchIDsByType}, nil
}

func (s *Service) finalizeScan(ctx context.Context, completion scanCompletion) (uuid.UUID, error) {
	completedAt := time.Now().UTC()
	finalStatus := "complete"
	errorMessage := ""
	eventType := events.ScanCompleted
	if len(completion.resolvedProviders) == 0 || completion.providerSucceeded == 0 {
		finalStatus = "failed"
		eventType = events.ScanFailed
		errorMessage = "all providers failed"
	}

	if completion.providerSucceeded > 0 {
		if err := s.markStaleMatchedVulnerabilities(ctx, completion.snapshotID, completion.freshMatchIDsByType); err != nil {
			return completion.scanID, s.failScan(ctx, completion.scanID, completion.snapshotID, err)
		}
	}

	if _, err := s.queries.UpdateScanStatus(ctx, dbgen.UpdateScanStatusParams{
		ID:           completion.scanID,
		Status:       finalStatus,
		ErrorMessage: errorMessage,
		StartedAt:    sql.NullTime{Time: completion.startedAt, Valid: true},
		CompletedAt:  sql.NullTime{Time: completedAt, Valid: true},
	}); err != nil {
		return completion.scanID, fmt.Errorf("update scan status: %w", err)
	}

	s.publish(ctx, eventType, map[string]any{
		"scan_id":          completion.scanID.String(),
		"snapshot_id":      completion.snapshotID.String(),
		"providers":        completion.resolvedProviders,
		"providers_failed": completion.providerFailed,
	})

	if finalStatus == "failed" {
		return completion.scanID, errors.New(errorMessage)
	}
	return completion.scanID, nil
}

func (s *Service) markStaleMatchedVulnerabilities(ctx context.Context, snapshotID uuid.UUID, freshMatchIDsByType map[string]map[uuid.UUID]struct{}) error {
	for vulnType, ids := range freshMatchIDsByType {
		if err := s.queries.MarkStaleVulnerabilities(ctx, snapshotID, vulnType, uniqueMatchIDs(ids)); err != nil {
			return fmt.Errorf("mark stale %s vulnerabilities: %w", vulnType, err)
		}
	}
	return nil
}

func mergeFreshMatchIDs(dst map[string]map[uuid.UUID]struct{}, src map[string][]uuid.UUID) {
	for vulnType, ids := range src {
		bucket := dst[vulnType]
		if bucket == nil {
			bucket = make(map[uuid.UUID]struct{})
			dst[vulnType] = bucket
		}
		for _, matchID := range ids {
			bucket[matchID] = struct{}{}
		}
	}
}

func newComponentMatchState(advisoryMap map[string]uuid.UUID) *componentMatchState {
	advisorySet := make(map[uuid.UUID]struct{}, len(advisoryMap))
	for _, advisoryID := range advisoryMap {
		advisorySet[advisoryID] = struct{}{}
	}
	return &componentMatchState{
		advisorySet:   advisorySet,
		rangeCache:    make(map[string][]dbgen.AffectedRange),
		advisoryCache: make(map[uuid.UUID]dbgen.Advisory, len(advisorySet)),
	}
}

func (s *Service) matchComponentRanges(ctx context.Context, snapshotID uuid.UUID, providerName string, component dbgen.Component, state *componentMatchState, freshMatchIDs map[string][]uuid.UUID) error {
	ranges, err := s.loadAffectedRangesForComponent(ctx, component, state)
	if err != nil {
		return err
	}
	for _, affectedRange := range ranges {
		if _, ok := state.advisorySet[affectedRange.AdvisoryID]; !ok {
			continue
		}
		if !s.componentMatchesAffectedRange(component, affectedRange) {
			continue
		}
		vulnerability, vulnType, err := s.createMatchedVulnerability(ctx, snapshotID, providerName, component, affectedRange, state)
		if err != nil {
			if isUniqueViolation(err) {
				continue
			}
			return fmt.Errorf("create vulnerability for component %s advisory %s: %w", component.ID, affectedRange.AdvisoryID, err)
		}
		freshMatchIDs[vulnType] = append(freshMatchIDs[vulnType], vulnerability.ID)
		s.publishMatchedVulnerability(ctx, snapshotID, affectedRange.AdvisoryID, vulnerability)
	}
	return nil
}

func (s *Service) loadAffectedRangesForComponent(ctx context.Context, component dbgen.Component, state *componentMatchState) ([]dbgen.AffectedRange, error) {
	cacheKey := packageKey(component.Ecosystem, component.Name)
	if ranges, ok := state.rangeCache[cacheKey]; ok {
		return ranges, nil
	}
	loaded, err := s.queries.ListAffectedRangesByPackage(ctx, dbgen.ListAffectedRangesByPackageParams{
		Ecosystem:   component.Ecosystem,
		PackageName: component.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("list affected ranges for %s/%s: %w", component.Ecosystem, component.Name, err)
	}
	state.rangeCache[cacheKey] = loaded
	return loaded, nil
}

func (s *Service) componentMatchesAffectedRange(component dbgen.Component, affectedRange dbgen.AffectedRange) bool {
	if !distroRangeApplies(component, affectedRange) {
		return false
	}
	affected, err := versioncmp.InRange(component.Ecosystem, component.Version, affectedRange.Introduced, affectedRange.Fixed, affectedRange.LastAffected)
	if err != nil {
		s.log.Warn().
			Err(err).
			Str("ecosystem", component.Ecosystem).
			Str("component", component.Name).
			Msg("skip version match")
		return false
	}
	return affected
}

func (s *Service) createMatchedVulnerability(ctx context.Context, snapshotID uuid.UUID, providerName string, component dbgen.Component, affectedRange dbgen.AffectedRange, state *componentMatchState) (*store.Vulnerability, string, error) {
	advisoryRecord, err := s.loadMatchedAdvisory(ctx, affectedRange.AdvisoryID, state)
	if err != nil {
		return nil, "", err
	}
	vulnType := matchedVulnerabilityType(advisoryRecord)
	vulnerability, err := s.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type:                   vulnType,
		SnapshotID:             snapshotID,
		Title:                  firstNonEmpty(strings.TrimSpace(advisoryRecord.Title), strings.TrimSpace(advisoryRecord.CanonicalID)),
		Description:            strings.TrimSpace(advisoryRecord.Description),
		PrimaryIdentifierKind:  "advisory",
		PrimaryIdentifierValue: strings.TrimSpace(advisoryRecord.CanonicalID),
		OriginalSeverity:       advisoryRecord.Severity,
		Severity:               advisoryRecord.Severity,
		Status:                 "detected",
		ScannerName:            providerName,
		Fingerprint:            dependencyFingerprint(affectedRange.AdvisoryID, component.ID),
		ComponentID:            uuid.NullUUID{UUID: component.ID, Valid: true},
		ComponentName:          sql.NullString{String: component.Name, Valid: strings.TrimSpace(component.Name) != ""},
		ComponentVersion:       sql.NullString{String: component.Version, Valid: strings.TrimSpace(component.Version) != ""},
		ComponentPurl:          sql.NullString{String: component.Purl, Valid: strings.TrimSpace(component.Purl) != ""},
		Ecosystem:              sql.NullString{String: component.Ecosystem, Valid: strings.TrimSpace(component.Ecosystem) != ""},
		AdvisoryID:             uuid.NullUUID{UUID: affectedRange.AdvisoryID, Valid: true},
		AffectedRangeID:        uuid.NullUUID{UUID: affectedRange.ID, Valid: true},
	})
	if err != nil {
		return nil, vulnType, err
	}
	return vulnerability, vulnType, nil
}

func (s *Service) loadMatchedAdvisory(ctx context.Context, advisoryID uuid.UUID, state *componentMatchState) (dbgen.Advisory, error) {
	if advisoryRecord, ok := state.advisoryCache[advisoryID]; ok {
		return advisoryRecord, nil
	}
	loaded, err := s.queries.GetAdvisoryByID(ctx, advisoryID)
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("load advisory %s: %w", advisoryID, err)
	}
	state.advisoryCache[advisoryID] = loaded
	return loaded, nil
}

func matchedVulnerabilityType(advisoryRecord dbgen.Advisory) string {
	if advisoryRecord.IsMalware {
		return "malware"
	}
	return "dependency"
}

func (s *Service) publishMatchedVulnerability(ctx context.Context, snapshotID, advisoryID uuid.UUID, vulnerability *store.Vulnerability) {
	// identifier is the human-facing id (CVE/GHSA/rule) — advisory_id is an
	// internal UUID and must never reach a notification body or a search link.
	payload := map[string]any{
		"id":          vulnerability.ID.String(),
		"org_id":      "",
		"snapshot_id": snapshotID.String(),
		"advisory_id": advisoryID.String(),
		"identifier":  strings.TrimSpace(vulnerability.PrimaryIdentifierValue),
		"severity":    strings.ToLower(string(vulnerability.Severity)),
		"type":        vulnerability.Type,
	}
	if vulnerability.ComponentName != nil && strings.TrimSpace(*vulnerability.ComponentName) != "" {
		component := strings.TrimSpace(*vulnerability.ComponentName)
		if vulnerability.ComponentVersion != nil && strings.TrimSpace(*vulnerability.ComponentVersion) != "" {
			component += "@" + strings.TrimSpace(*vulnerability.ComponentVersion)
		}
		payload["component"] = component
	}
	s.publish(ctx, events.VulnerabilityCreated, payload)
}

func (s *Service) failScan(ctx context.Context, scanID, snapshotID uuid.UUID, err error) error {
	completedAt := time.Now().UTC()
	if _, updateErr := s.queries.UpdateScanStatus(ctx, dbgen.UpdateScanStatusParams{
		ID:           scanID,
		Status:       "failed",
		ErrorMessage: err.Error(),
		CompletedAt:  sql.NullTime{Time: completedAt, Valid: true},
	}); updateErr != nil {
		return fmt.Errorf("%w; update scan failure: %w", err, updateErr)
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
	responseTime := int32(completedAt.Sub(startedAt) / time.Millisecond) //nolint:gosec // G115: scan provider response times are operationally bounded.
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
		// Normalize to "family-version" (family always present, from the purl
		// namespace) so every provider parses the distro identically regardless
		// of whether Trivy emitted the family in the qualifier.
		distroQualifier := ""
		if family, release := distro.FromPurl(component.Purl); family != "" && release != "" {
			distroQualifier = family + "-" + release
		}
		queries = append(queries, provider.PackageQuery{
			Ecosystem: component.Ecosystem,
			Name:      component.Name,
			Version:   component.Version,
			Distro:    distroQualifier,
		})
	}
	return queries
}

// distroRangeApplies enforces release scoping for OS packages: a distro range
// is only comparable to a component from the same distribution release (Alpine
// 3.18's fix version says nothing about 3.19). Fails closed when either side's
// release is unknown; language ecosystems are unaffected.
func distroRangeApplies(component dbgen.Component, affectedRange dbgen.AffectedRange) bool {
	if !distro.IsDistroEcosystem(component.Ecosystem) {
		return true
	}
	if affectedRange.Release == "" {
		// Trivy-sourced ranges are synthesized against the component's own
		// installed version and carry the release the component was scanned
		// with, so an empty release only appears on data that cannot be scoped —
		// which must not match.
		return false
	}
	_, release := distro.FromPurl(component.Purl)
	return distro.ReleaseKey(component.Ecosystem, release) == affectedRange.Release
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

func dependencyFingerprint(advisoryID, componentID uuid.UUID) string {
	sum := sha256.Sum256([]byte(advisoryID.String() + ":" + componentID.String()))
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}
