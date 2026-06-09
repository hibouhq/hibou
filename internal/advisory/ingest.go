package advisory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	storepkg "github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

var cveAliasPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)

type IngesterStore interface {
	BeginTx(ctx context.Context) (*sql.Tx, error)
	GetAdvisoryByAlias(ctx context.Context, alias string) (dbgen.Advisory, error)
	UpsertAdvisory(ctx context.Context, arg dbgen.UpsertAdvisoryParams) (dbgen.Advisory, error)
	UpdateAdvisoryCanonicalID(ctx context.Context, arg dbgen.UpdateAdvisoryCanonicalIDParams) error
	UpsertAdvisoryAlias(ctx context.Context, arg dbgen.UpsertAdvisoryAliasParams) error
	UpsertAdvisorySource(ctx context.Context, arg dbgen.UpsertAdvisorySourceParams) error
	ListSourcesByAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]dbgen.AdvisorySource, error)
	CreateAffectedRange(ctx context.Context, arg dbgen.CreateAffectedRangeParams) (dbgen.AffectedRange, error)
	DeleteAffectedRangesByAdvisoryAndSource(ctx context.Context, arg dbgen.DeleteAffectedRangesByAdvisoryAndSourceParams) error
}

type Ingester struct {
	queries IngesterStore
	withTx  func(tx *sql.Tx) IngesterStore
	log     zerolog.Logger
}

type IngestResult struct {
	ProviderID     string
	Aliases        []string
	Title          string
	Description    string
	Severity       *Severity
	CVSSScore      *float64
	CVSSVersion    *CVSSVersion
	CVSSVector     string
	CWEIDs         []string
	IsMalware      bool
	MalwareType    *string
	AffectedRanges []AffectedRange
	PublishedAt    *time.Time
	WithdrawnAt    *time.Time
	RawData        json.RawMessage
}

func NewIngester(store IngesterStore, log zerolog.Logger) *Ingester {
	ingester := &Ingester{
		queries: store,
		log:     log.With().Str("component", "advisory.ingester").Logger(),
	}
	if txStore, ok := store.(interface {
		WithTx(tx *sql.Tx) *storepkg.Queries
	}); ok {
		ingester.withTx = func(tx *sql.Tx) IngesterStore {
			return txStore.WithTx(tx)
		}
	}
	return ingester
}

func (ing *Ingester) Ingest(ctx context.Context, providerName string, results []IngestResult) (map[string]uuid.UUID, error) {
	advisoryIDs := make(map[string]uuid.UUID, len(results))
	var ingestErrs []error
	for _, result := range results {
		advisoryRecord, err := ing.ingestOne(ctx, providerName, result)
		if err != nil {
			ing.log.Error().Err(err).Str("provider", providerName).Str("provider_id", result.ProviderID).Msg("ingest advisory failed")
			ingestErrs = append(ingestErrs, err)
			continue
		}
		advisoryIDs[result.ProviderID] = advisoryRecord.ID
	}
	if len(ingestErrs) > 0 && len(advisoryIDs) == 0 {
		return nil, errors.Join(ingestErrs...)
	}
	return advisoryIDs, nil
}

func (ing *Ingester) ingestOne(ctx context.Context, providerName string, result IngestResult) (dbgen.Advisory, error) {
	tx, queries, committed, err := ing.beginIngestTx(ctx, providerName, result)
	if err != nil {
		return dbgen.Advisory{}, err
	}
	defer rollbackAdvisoryTx(tx, &committed)

	canonicalID := preferredCanonicalID(result)
	existing, found, err := ing.findExistingAdvisory(ctx, result)
	if err != nil {
		return dbgen.Advisory{}, err
	}
	canonicalID, existing, err = ing.reconcileCanonicalID(ctx, queries, existing, found, canonicalID)
	if err != nil {
		return dbgen.Advisory{}, err
	}

	base := mergedAdvisoryUpsert(existing, found, canonicalID, result)
	advisoryRecord, err := queries.UpsertAdvisory(ctx, base)
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("upsert advisory %s: %w", canonicalID, err)
	}

	if err := ing.syncAdvisorySources(ctx, queries, advisoryRecord.ID, providerName, result); err != nil {
		return dbgen.Advisory{}, err
	}
	finalRecord, err := ing.finalizeAdvisoryRecord(ctx, queries, advisoryRecord, canonicalID, result)
	if err != nil {
		return dbgen.Advisory{}, err
	}

	if tx != nil {
		if err := tx.Commit(); err != nil {
			return dbgen.Advisory{}, fmt.Errorf("commit advisory %s: %w", canonicalID, err)
		}
		committed = true
	}

	ing.log.Debug().
		Str("provider", providerName).
		Str("provider_id", result.ProviderID).
		Str("advisory_id", finalRecord.ID.String()).
		Msg("ingested advisory")

	return finalRecord, nil
}

func (ing *Ingester) beginIngestTx(ctx context.Context, providerName string, result IngestResult) (*sql.Tx, IngesterStore, bool, error) {
	tx, err := ing.queries.BeginTx(ctx)
	if err != nil {
		return nil, nil, false, fmt.Errorf("begin advisory transaction for %s/%s: %w", providerName, result.ProviderID, err)
	}
	queries := ing.queries
	if tx != nil && ing.withTx != nil {
		queries = ing.withTx(tx)
	}
	return tx, queries, false, nil
}

func rollbackAdvisoryTx(tx *sql.Tx, committed *bool) {
	if tx != nil && !*committed {
		_ = tx.Rollback()
	}
}

func (ing *Ingester) reconcileCanonicalID(ctx context.Context, queries IngesterStore, existing dbgen.Advisory, found bool, canonicalID string) (string, dbgen.Advisory, error) {
	if found && shouldPromoteCanonicalID(existing.CanonicalID, canonicalID) {
		if err := queries.UpdateAdvisoryCanonicalID(ctx, dbgen.UpdateAdvisoryCanonicalIDParams{
			AdvisoryID:  existing.ID,
			CanonicalID: canonicalID,
		}); err != nil {
			return "", dbgen.Advisory{}, fmt.Errorf("promote advisory canonical ID %s -> %s: %w", existing.CanonicalID, canonicalID, err)
		}
		existing.CanonicalID = canonicalID
	}
	if found && !shouldPromoteCanonicalID(existing.CanonicalID, canonicalID) {
		canonicalID = existing.CanonicalID
	}
	return canonicalID, existing, nil
}

func (ing *Ingester) syncAdvisorySources(ctx context.Context, queries IngesterStore, advisoryID uuid.UUID, providerName string, result IngestResult) error {
	if err := ing.upsertAdvisoryAliases(ctx, queries, advisoryID, result); err != nil {
		return err
	}
	if err := queries.UpsertAdvisorySource(ctx, dbgen.UpsertAdvisorySourceParams{
		AdvisoryID:  advisoryID,
		Provider:    providerName,
		ProviderID:  result.ProviderID,
		Severity:    toNullSeverityLevel(result.Severity),
		CvssScore:   toNullScore(result.CVSSScore),
		CvssVersion: toNullCVSSVersion(result.CVSSVersion),
		CvssVector:  result.CVSSVector,
		RawData:     result.RawData,
		FetchedAt:   time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("upsert advisory source %s/%s: %w", providerName, result.ProviderID, err)
	}
	if err := ing.replaceAffectedRanges(ctx, queries, advisoryID, providerName, result.AffectedRanges); err != nil {
		return err
	}
	return nil
}

func (ing *Ingester) upsertAdvisoryAliases(ctx context.Context, queries IngesterStore, advisoryID uuid.UUID, result IngestResult) error {
	for _, alias := range uniqueAliases(result.ProviderID, result.Aliases) {
		if err := queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisoryID, Alias: alias}); err != nil {
			return fmt.Errorf("upsert advisory alias %s: %w", alias, err)
		}
	}
	return nil
}

func (ing *Ingester) replaceAffectedRanges(ctx context.Context, queries IngesterStore, advisoryID uuid.UUID, providerName string, ranges []AffectedRange) error {
	if err := queries.DeleteAffectedRangesByAdvisoryAndSource(ctx, dbgen.DeleteAffectedRangesByAdvisoryAndSourceParams{
		AdvisoryID: advisoryID,
		Source:     providerName,
	}); err != nil {
		return fmt.Errorf("delete affected ranges for %s/%s: %w", providerName, advisoryID, err)
	}
	for _, affectedRange := range ranges {
		if _, err := queries.CreateAffectedRange(ctx, dbgen.CreateAffectedRangeParams{
			AdvisoryID:   advisoryID,
			Ecosystem:    affectedRange.Ecosystem,
			PackageName:  affectedRange.PackageName,
			Introduced:   affectedRange.Introduced,
			Fixed:        affectedRange.Fixed,
			LastAffected: affectedRange.LastAffected,
			Source:       providerName,
		}); err != nil {
			return fmt.Errorf("create affected range for %s/%s: %w", providerName, advisoryID, err)
		}
	}
	return nil
}

func (ing *Ingester) finalizeAdvisoryRecord(ctx context.Context, queries IngesterStore, advisoryRecord dbgen.Advisory, canonicalID string, result IngestResult) (dbgen.Advisory, error) {
	sources, err := queries.ListSourcesByAdvisory(ctx, advisoryRecord.ID)
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("list advisory sources for %s: %w", advisoryRecord.ID, err)
	}
	mergedSeverity, mergedScore, mergedVector := MergeSeverity(convertSources(sources))
	mergedVersion := selectCanonicalCVSSVersion(sources)
	finalRecord, err := queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: canonicalID,
		Title:       advisoryRecord.Title,
		Description: advisoryRecord.Description,
		Severity:    toSeverityLevel(mergedSeverity),
		CvssScore:   toNullScore(mergedScore),
		CvssVersion: toNullCVSSVersion(mergedVersion),
		CvssVector:  mergedVector,
		CweIds:      advisoryRecord.CweIds,
		IsMalware:   advisoryRecord.IsMalware || result.IsMalware,
		MalwareType: coalesceMalwareType(advisoryRecord.MalwareType, normalizeMalwareType(result.MalwareType)),
		PublishedAt: advisoryRecord.PublishedAt,
		WithdrawnAt: advisoryRecord.WithdrawnAt,
	})
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("update canonical advisory %s: %w", canonicalID, err)
	}
	return finalRecord, nil
}

func (ing *Ingester) findExistingAdvisory(ctx context.Context, result IngestResult) (dbgen.Advisory, bool, error) {
	for _, alias := range uniqueAliases(result.ProviderID, result.Aliases) {
		advisoryRecord, err := ing.queries.GetAdvisoryByAlias(ctx, alias)
		if err == nil {
			return advisoryRecord, true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return dbgen.Advisory{}, false, fmt.Errorf("lookup advisory by alias %s: %w", alias, err)
		}
	}
	return dbgen.Advisory{}, false, nil
}

func preferredCanonicalID(result IngestResult) string {
	for _, alias := range result.Aliases {
		if cveAliasPattern.MatchString(strings.TrimSpace(alias)) {
			return strings.ToUpper(strings.TrimSpace(alias))
		}
	}
	return strings.TrimSpace(result.ProviderID)
}

func shouldPromoteCanonicalID(existingCanonicalID, nextCanonicalID string) bool {
	return cveAliasPattern.MatchString(strings.TrimSpace(nextCanonicalID)) && !cveAliasPattern.MatchString(strings.TrimSpace(existingCanonicalID))
}

func mergedAdvisoryUpsert(existing dbgen.Advisory, found bool, canonicalID string, result IngestResult) dbgen.UpsertAdvisoryParams {
	title := strings.TrimSpace(result.Title)
	if title == "" && found {
		title = existing.Title
	}

	description := strings.TrimSpace(result.Description)
	if description == "" && found {
		description = existing.Description
	}

	severity := severityForResult(result)
	if found {
		severity = existing.Severity
	}

	malwareType := normalizeMalwareType(result.MalwareType)
	if found {
		malwareType = coalesceMalwareType(existing.MalwareType, malwareType)
	}

	publishedAt := toNullTime(result.PublishedAt)
	if found && !publishedAt.Valid {
		publishedAt = existing.PublishedAt
	}

	withdrawnAt := toNullTime(result.WithdrawnAt)
	if found && !withdrawnAt.Valid {
		withdrawnAt = existing.WithdrawnAt
	}

	return dbgen.UpsertAdvisoryParams{
		CanonicalID: canonicalID,
		Title:       title,
		Description: description,
		Severity:    severity,
		CvssScore:   toNullScore(result.CVSSScore),
		CvssVersion: toNullCVSSVersion(result.CVSSVersion),
		CvssVector:  result.CVSSVector,
		CweIds:      mergeStrings(existing.CweIds, result.CWEIDs),
		IsMalware:   (found && existing.IsMalware) || result.IsMalware,
		MalwareType: malwareType,
		PublishedAt: publishedAt,
		WithdrawnAt: withdrawnAt,
	}
}

func convertSources(sources []dbgen.AdvisorySource) []Source {
	converted := make([]Source, 0, len(sources))
	for _, source := range sources {
		converted = append(converted, Source{
			ID:          source.ID,
			AdvisoryID:  source.AdvisoryID,
			Provider:    source.Provider,
			ProviderID:  source.ProviderID,
			Severity:    fromNullSeverityLevel(source.Severity),
			CVSSScore:   fromNullScore(source.CvssScore),
			CVSSVersion: fromNullCVSSVersion(source.CvssVersion),
			CVSSVector:  source.CvssVector,
			RawData:     source.RawData,
			FetchedAt:   source.FetchedAt,
		})
	}
	return converted
}

func selectCanonicalCVSSVersion(sources []dbgen.AdvisorySource) *CVSSVersion {
	best := selectCanonicalSource(sources)
	if best == nil || !best.CvssVersion.Valid {
		return nil
	}
	version := CVSSVersion(best.CvssVersion.CvssVersion)
	return &version
}

func selectCanonicalSource(sources []dbgen.AdvisorySource) *dbgen.AdvisorySource {
	var best *dbgen.AdvisorySource
	for i := range sources {
		source := &sources[i]
		if !dbSourceHasSignal(source) || shouldSkipCanonicalSource(best, source) {
			continue
		}
		if preferCanonicalNVD(best, source) {
			best = source
			continue
		}
		if best == nil || compareSourcePriority(*source, *best) > 0 {
			best = source
		}
	}
	return best
}

func shouldSkipCanonicalSource(best *dbgen.AdvisorySource, source *dbgen.AdvisorySource) bool {
	return best != nil && strings.EqualFold(best.Provider, "nvd") && !strings.EqualFold(source.Provider, "nvd")
}

func preferCanonicalNVD(best *dbgen.AdvisorySource, source *dbgen.AdvisorySource) bool {
	return strings.EqualFold(source.Provider, "nvd") && (best == nil || !strings.EqualFold(best.Provider, "nvd"))
}

func dbSourceHasSignal(source *dbgen.AdvisorySource) bool {
	return source.CvssScore.Valid || source.Severity.Valid
}

func compareSourcePriority(left, right dbgen.AdvisorySource) int {
	if cmp := compareScoreStrings(left.CvssScore, right.CvssScore); cmp != 0 {
		return cmp
	}

	leftSeverity := severityLevelFromSource(left)
	rightSeverity := severityLevelFromSource(right)
	if cmp := compareSeverityLevels(leftSeverity, rightSeverity); cmp != 0 {
		return cmp
	}

	if left.CvssVector != "" && right.CvssVector == "" {
		return 1
	}
	if left.CvssVector == "" && right.CvssVector != "" {
		return -1
	}

	return strings.Compare(strings.ToLower(right.Provider), strings.ToLower(left.Provider))
}

func compareScoreStrings(left, right sql.NullString) int {
	if left.Valid && !right.Valid {
		return 1
	}
	if !left.Valid && right.Valid {
		return -1
	}
	if !left.Valid && !right.Valid {
		return 0
	}

	leftValue, leftErr := strconv.ParseFloat(left.String, 64)
	rightValue, rightErr := strconv.ParseFloat(right.String, 64)
	if leftErr != nil || rightErr != nil {
		return strings.Compare(left.String, right.String)
	}
	if leftValue > rightValue {
		return 1
	}
	if leftValue < rightValue {
		return -1
	}
	return 0
}

func severityLevelFromSource(source dbgen.AdvisorySource) dbgen.SeverityLevel {
	if source.CvssScore.Valid {
		if score, err := strconv.ParseFloat(source.CvssScore.String, 64); err == nil {
			return toSeverityLevel(NormalizeSeverity(score))
		}
	}
	if source.Severity.Valid {
		return source.Severity.SeverityLevel
	}
	return dbgen.SeverityLevelInfo
}

func compareSeverityLevels(left, right dbgen.SeverityLevel) int {
	if severityLevelRank(left) > severityLevelRank(right) {
		return 1
	}
	if severityLevelRank(left) < severityLevelRank(right) {
		return -1
	}
	return 0
}

func severityLevelRank(severity dbgen.SeverityLevel) int {
	switch severity {
	case dbgen.SeverityLevelCritical:
		return 5
	case dbgen.SeverityLevelHigh:
		return 4
	case dbgen.SeverityLevelMedium:
		return 3
	case dbgen.SeverityLevelLow:
		return 2
	default:
		return 1
	}
}

func severityForResult(result IngestResult) dbgen.SeverityLevel {
	if result.Severity != nil {
		return toSeverityLevel(*result.Severity)
	}
	if result.CVSSScore != nil {
		return toSeverityLevel(NormalizeSeverity(*result.CVSSScore))
	}
	return dbgen.SeverityLevelInfo
}

func toSeverityLevel(severity Severity) dbgen.SeverityLevel {
	return dbgen.SeverityLevel(severity)
}

func toNullSeverityLevel(severity *Severity) dbgen.NullSeverityLevel {
	if severity == nil {
		return dbgen.NullSeverityLevel{}
	}
	return dbgen.NullSeverityLevel{SeverityLevel: toSeverityLevel(*severity), Valid: true}
}

func fromNullSeverityLevel(severity dbgen.NullSeverityLevel) *Severity {
	if !severity.Valid {
		return nil
	}
	converted := Severity(severity.SeverityLevel)
	return &converted
}

func toNullScore(score *float64) sql.NullString {
	if score == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: strconv.FormatFloat(*score, 'f', -1, 64), Valid: true}
}

func fromNullScore(score sql.NullString) *float64 {
	if !score.Valid {
		return nil
	}
	parsed, err := strconv.ParseFloat(score.String, 64)
	if err != nil {
		return nil
	}
	return &parsed
}

func toNullCVSSVersion(version *CVSSVersion) dbgen.NullCvssVersion {
	if version == nil {
		return dbgen.NullCvssVersion{}
	}
	return dbgen.NullCvssVersion{CvssVersion: dbgen.CvssVersion(*version), Valid: true}
}

func fromNullCVSSVersion(version dbgen.NullCvssVersion) *CVSSVersion {
	if !version.Valid {
		return nil
	}
	converted := CVSSVersion(version.CvssVersion)
	return &converted
}

func toNullTime(ts *time.Time) sql.NullTime {
	if ts == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: ts.UTC(), Valid: true}
}

func normalizeMalwareType(value *string) dbgen.NullMalwareType {
	if value == nil {
		return dbgen.NullMalwareType{}
	}
	normalized := strings.ToLower(strings.TrimSpace(*value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	malwareType := dbgen.MalwareTypeOther
	switch normalized {
	case string(dbgen.MalwareTypeTyposquat):
		malwareType = dbgen.MalwareTypeTyposquat
	case string(dbgen.MalwareTypeDependencyConfusion):
		malwareType = dbgen.MalwareTypeDependencyConfusion
	case string(dbgen.MalwareTypeBackdoor):
		malwareType = dbgen.MalwareTypeBackdoor
	case string(dbgen.MalwareTypeCryptominer):
		malwareType = dbgen.MalwareTypeCryptominer
	case string(dbgen.MalwareTypeDataExfiltration):
		malwareType = dbgen.MalwareTypeDataExfiltration
	}
	return dbgen.NullMalwareType{MalwareType: malwareType, Valid: true}
}

func coalesceMalwareType(values ...dbgen.NullMalwareType) dbgen.NullMalwareType {
	for _, value := range values {
		if value.Valid {
			return value
		}
	}
	return dbgen.NullMalwareType{}
}

func uniqueAliases(providerID string, aliases []string) []string {
	seen := make(map[string]struct{}, len(aliases)+1)
	ordered := make([]string, 0, len(aliases)+1)
	for _, alias := range append([]string{providerID}, aliases...) {
		trimmed := strings.TrimSpace(alias)
		if trimmed == "" {
			continue
		}
		key := strings.ToUpper(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ordered = append(ordered, trimmed)
	}
	return ordered
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]string, 0, len(left)+len(right))
	for _, value := range append(append([]string(nil), left...), right...) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToUpper(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, trimmed)
	}
	return merged
}
