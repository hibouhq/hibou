package advisory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// RatingStore is what re-rating needs (ADR-038 §2).
type RatingStore interface {
	GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error)
	SyncAdvisorySourceRatings(ctx context.Context, arg dbgen.SyncAdvisorySourceRatingsParams) error
	ListAdvisoryRatings(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.ListAdvisoryRatingsRow, error)
	SetAdvisoryRating(ctx context.Context, arg dbgen.SetAdvisoryRatingParams) (dbgen.Advisory, error)
	ListFindingsForRating(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.ListFindingsForRatingRow, error)
	SetFindingRating(ctx context.Context, arg dbgen.SetFindingRatingParams) error
	ListCVERatingsForAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]dbgen.ListCVERatingsForAdvisoryRow, error)
	UpsertCVEAdvisorySource(ctx context.Context, arg dbgen.UpsertCVEAdvisorySourceParams) (uuid.UUID, error)
	DeleteCVEAdvisorySource(ctx context.Context, advisoryID uuid.UUID) error
}

// CVEProvider names the advisory source the CVE feed's rating is stored
// under.
const CVEProvider = "cve"

// Rerate brings an advisory and every finding of it in line with its
// ratings: it refreshes the CVE-feed rating, recomputes the headline (rule
// 2), then each finding's own choice (rule 1 for OS packages). Ingest, the
// startup backfill and the CVE-feed reconcile all call it, so there is one
// way a severity is derived. Rows that would not change are not written.
func Rerate(ctx context.Context, q RatingStore, advisoryID uuid.UUID) (dbgen.Advisory, error) {
	if err := syncCVERating(ctx, q, advisoryID); err != nil {
		return dbgen.Advisory{}, err
	}
	record, err := q.GetAdvisoryByID(ctx, advisoryID)
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("load advisory: %w", err)
	}
	rows, err := q.ListAdvisoryRatings(ctx, []uuid.UUID{advisoryID})
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("list ratings: %w", err)
	}
	ratings := RatingsFromRows(rows)

	headline := withMalwareFloor(Headline(ratings), record.IsMalware)
	if !sameAdvisoryRating(record, headline) {
		record, err = q.SetAdvisoryRating(ctx, advisoryRatingParams(advisoryID, headline))
		if err != nil {
			return dbgen.Advisory{}, fmt.Errorf("set advisory rating: %w", err)
		}
	}

	findings, err := q.ListFindingsForRating(ctx, []uuid.UUID{advisoryID})
	if err != nil {
		return dbgen.Advisory{}, fmt.Errorf("list findings: %w", err)
	}
	for _, finding := range findings {
		choice := withMalwareFloor(ForFinding(ratings, finding.Ecosystem.String, finding.ComponentPurl.String), record.IsMalware)
		if sameFindingRating(finding, choice) {
			continue
		}
		if err := q.SetFindingRating(ctx, findingRatingParams(finding.ID, choice)); err != nil {
			return dbgen.Advisory{}, fmt.Errorf("set finding rating: %w", err)
		}
	}
	return record, nil
}

// SyncSourceRatings replaces one source's stored ratings.
func SyncSourceRatings(ctx context.Context, q RatingStore, sourceID uuid.UUID, ratings []Rating) error {
	return q.SyncAdvisorySourceRatings(ctx, ratingsParams(sourceID, ratings))
}

// FindingRating is the rating a new dependency finding copies at match time.
func FindingRating(ratings []Rating, isMalware bool, ecosystem, purl string) Choice {
	return withMalwareFloor(ForFinding(ratings, ecosystem, purl), isMalware)
}

// syncCVERating stores the CVE feed's rating of the advisory's CVE as its
// 'cve' source, or removes it when the feed rates none of its CVEs.
func syncCVERating(ctx context.Context, q RatingStore, advisoryID uuid.UUID) error {
	records, err := q.ListCVERatingsForAdvisory(ctx, advisoryID)
	if err != nil {
		return fmt.Errorf("list cve ratings: %w", err)
	}
	if len(records) == 0 {
		return q.DeleteCVEAdvisorySource(ctx, advisoryID)
	}
	best := records[0]
	// raw_data mirrors the cve_records columns verbatim: the reconcile query
	// compares the two to find stale ratings.
	raw, err := json.Marshal(map[string]string{
		"cve_id":   best.CveID,
		"vector":   best.CvssVector,
		"score":    best.CvssScore.String,
		"severity": best.Severity,
		"source":   best.CvssSource,
	})
	if err != nil {
		return err
	}
	sourceID, err := q.UpsertCVEAdvisorySource(ctx, dbgen.UpsertCVEAdvisorySourceParams{
		AdvisoryID:     advisoryID,
		ProviderID:     best.CveID,
		RawData:        raw,
		RatingsVersion: RatingsVersion,
	})
	if err != nil {
		return fmt.Errorf("store cve source: %w", err)
	}
	return q.SyncAdvisorySourceRatings(ctx, ratingsParams(sourceID, CVERatings(best.CvssSource, best.CvssVector, parseScore(best.CvssScore), best.Severity)))
}

// CVERatings maps the CVE feed's strongest rating. The container's short name
// is the rater (a CNA, or CISA-ADP); an unnamed one is "cve".
func CVERatings(source, vector string, score *float64, label string) []Rating {
	rater := source
	if strings.TrimSpace(rater) == "" {
		rater = CVEProvider
	}
	rating, ok := NewRating(rater, vector, score, ParseLabel(label))
	if !ok {
		return nil
	}
	return []Rating{rating}
}

// ParseLabel reads a severity word in any rater's vocabulary. Debian's
// "unimportant" and Ubuntu's "negligible" are low, not info: the vendor
// still calls it a flaw (ADR-038 §2). Unrecognized words are not evidence of
// anything and yield nil.
func ParseLabel(raw string) *Severity {
	var severity Severity
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		severity = SeverityCritical
	case "high", "important":
		severity = SeverityHigh
	case "medium", "moderate":
		severity = SeverityMedium
	case "low", "unimportant", "negligible":
		severity = SeverityLow
	case "info", "informational", "none":
		severity = SeverityInfo
	default:
		return nil
	}
	return &severity
}

// RatingsFromRows converts stored ratings.
func RatingsFromRows(rows []dbgen.ListAdvisoryRatingsRow) []Rating {
	ratings := make([]Rating, 0, len(rows))
	for _, row := range rows {
		ratings = append(ratings, Rating{
			Rater:    row.Rater,
			Version:  fromNullCVSSVersion(row.CvssVersion),
			Vector:   row.CvssVector,
			Score:    parseScore(row.CvssScore),
			Label:    fromNullSeverityLevel(row.Label),
			Provider: row.Provider,
		})
	}
	return ratings
}

func ratingsParams(sourceID uuid.UUID, ratings []Rating) dbgen.SyncAdvisorySourceRatingsParams {
	params := dbgen.SyncAdvisorySourceRatingsParams{
		AdvisorySourceID: sourceID,
		Raters:           []string{},
		Versions:         []string{},
		Vectors:          []string{},
		Scores:           []string{},
		Labels:           []string{},
	}
	seen := make(map[string]bool, len(ratings))
	for _, rating := range ratings {
		version := ""
		if rating.Version != nil {
			version = string(*rating.Version)
		}
		key := rating.Rater + "\x00" + version
		if seen[key] {
			continue // one row per rater and version; the first wins
		}
		seen[key] = true
		score, label := "", ""
		if rating.Score != nil {
			score = strconv.FormatFloat(*rating.Score, 'f', 1, 64)
		}
		if rating.Label != nil {
			label = string(*rating.Label)
		}
		params.Raters = append(params.Raters, rating.Rater)
		params.Versions = append(params.Versions, version)
		params.Vectors = append(params.Vectors, rating.Vector)
		params.Scores = append(params.Scores, score)
		params.Labels = append(params.Labels, label)
	}
	return params
}

func withMalwareFloor(choice Choice, isMalware bool) Choice {
	// MAL-* records carry no CVSS; a malicious package is critical by
	// definition, and blocked unconditionally rather than rated.
	if isMalware {
		choice.Severity = SeverityCritical
	}
	return choice
}

func choiceColumns(choice Choice) (dbgen.SeverityLevel, storedChoice) {
	cols := storedChoice{}
	if choice.Rating != nil {
		cols.score = toNullScore(choice.Rating.Score)
		cols.version = toNullCVSSVersion(choice.Rating.Version)
		cols.vector = choice.Rating.Vector
		cols.ratedBy = choice.Rating.Rater
	}
	return dbgen.SeverityLevel(choice.Severity), cols
}

// storedChoice is a choice's CVSS columns as stored.
type storedChoice struct {
	score   nullScore
	version dbgen.NullCvssVersion
	vector  string
	ratedBy string
}

func advisoryRatingParams(id uuid.UUID, choice Choice) dbgen.SetAdvisoryRatingParams {
	severity, cols := choiceColumns(choice)
	return dbgen.SetAdvisoryRatingParams{
		AdvisoryID:  id,
		Severity:    severity,
		CvssScore:   cols.score,
		CvssVersion: cols.version,
		CvssVector:  cols.vector,
		RatedBy:     cols.ratedBy,
	}
}

func findingRatingParams(id uuid.UUID, choice Choice) dbgen.SetFindingRatingParams {
	severity, cols := choiceColumns(choice)
	return dbgen.SetFindingRatingParams{
		ID:          id,
		Severity:    severity,
		CvssScore:   cols.score,
		CvssVersion: cols.version,
		CvssVector:  cols.vector,
		RatedBy:     cols.ratedBy,
	}
}

func sameAdvisoryRating(record dbgen.Advisory, choice Choice) bool {
	severity, cols := choiceColumns(choice)
	return record.Severity == severity && sameScore(record.CvssScore, cols.score) &&
		record.CvssVersion == cols.version && record.CvssVector == cols.vector && record.RatedBy == cols.ratedBy
}

func sameFindingRating(finding dbgen.ListFindingsForRatingRow, choice Choice) bool {
	severity, cols := choiceColumns(choice)
	current := finding.Severity
	if finding.Overridden {
		current = severity // an override keeps its severity; compare the rest
	}
	return current == severity && finding.OriginalSeverity == severity && sameScore(finding.CvssScore, cols.score) &&
		finding.CvssVersion == cols.version && finding.CvssVector == cols.vector && finding.RatedBy == cols.ratedBy
}

func sameScore(left, right nullScore) bool {
	if left.Valid != right.Valid {
		return false
	}
	if !left.Valid {
		return true
	}
	a, errA := strconv.ParseFloat(left.String, 64)
	b, errB := strconv.ParseFloat(right.String, 64)
	return errA == nil && errB == nil && math.Abs(a-b) < 0.001
}

// NullScore and NullCVSSVersion encode a rating's columns for callers that
// write findings themselves (the scanner).
func NullScore(score *float64) sql.NullString { return toNullScore(score) }

func NullCVSSVersion(version *CVSSVersion) dbgen.NullCvssVersion { return toNullCVSSVersion(version) }

// nullScore is a numeric column as sqlc reads it.
type nullScore = sql.NullString

func parseScore(value nullScore) *float64 {
	return fromNullScore(value)
}
