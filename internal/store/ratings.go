package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/epss"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Ratings and EPSS (ADR-038). Thin wrappers: the rules live in
// internal/advisory, the SQL in queries/ratings.sql.

func (q *Queries) SyncAdvisorySourceRatings(ctx context.Context, arg dbgen.SyncAdvisorySourceRatingsParams) error {
	return q.db.SyncAdvisorySourceRatings(ctx, arg)
}

func (q *Queries) ListAdvisoryRatings(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.ListAdvisoryRatingsRow, error) {
	return q.db.ListAdvisoryRatings(ctx, advisoryIDs)
}

func (q *Queries) SetAdvisoryRating(ctx context.Context, arg dbgen.SetAdvisoryRatingParams) (dbgen.Advisory, error) {
	return q.db.SetAdvisoryRating(ctx, arg)
}

func (q *Queries) ListFindingsForRating(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.ListFindingsForRatingRow, error) {
	return q.db.ListFindingsForRating(ctx, advisoryIDs)
}

func (q *Queries) SetFindingRating(ctx context.Context, arg dbgen.SetFindingRatingParams) error {
	return q.db.SetFindingRating(ctx, arg)
}

func (q *Queries) ListCVERatingsForAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]dbgen.ListCVERatingsForAdvisoryRow, error) {
	return q.db.ListCVERatingsForAdvisory(ctx, advisoryID)
}

func (q *Queries) UpsertCVEAdvisorySource(ctx context.Context, arg dbgen.UpsertCVEAdvisorySourceParams) (uuid.UUID, error) {
	return q.db.UpsertCVEAdvisorySource(ctx, arg)
}

func (q *Queries) DeleteCVEAdvisorySource(ctx context.Context, advisoryID uuid.UUID) error {
	return q.db.DeleteCVEAdvisorySource(ctx, advisoryID)
}

func (q *Queries) ListAdvisorySourcesForRatings(ctx context.Context, arg dbgen.ListAdvisorySourcesForRatingsParams) ([]dbgen.ListAdvisorySourcesForRatingsRow, error) {
	return q.db.ListAdvisorySourcesForRatings(ctx, arg)
}

func (q *Queries) SetAdvisorySourceRatingsVersion(ctx context.Context, arg dbgen.SetAdvisorySourceRatingsVersionParams) error {
	return q.db.SetAdvisorySourceRatingsVersion(ctx, arg)
}

func (q *Queries) ListAdvisoriesWithStaleCVERating(ctx context.Context, batchSize int32) ([]uuid.UUID, error) {
	return q.db.ListAdvisoriesWithStaleCVERating(ctx, batchSize)
}

func (q *Queries) ListEPSSForAdvisories(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.ListEPSSForAdvisoriesRow, error) {
	return q.db.ListEPSSForAdvisories(ctx, advisoryIDs)
}

func (q *Queries) GetEPSSCatalog(ctx context.Context) (dbgen.EpssCatalog, error) {
	return q.db.GetEPSSCatalog(ctx)
}

// EPSSReplaceResult reports what ReplaceEPSS did.
type EPSSReplaceResult struct {
	Replaced bool
	Rows     int
}

// ReplaceEPSS swaps the whole EPSS mirror for catalog in one transaction, so
// readers see yesterday's scores or today's, never a mix. A catalog no newer
// than the mirror's is skipped: the file republishes the same day under the
// same URL.
func (q *Queries) ReplaceEPSS(ctx context.Context, db *sql.DB, catalog epss.Catalog) (EPSSReplaceResult, error) {
	if current, err := q.db.GetEPSSCatalog(ctx); err == nil && !catalog.ScoreDate.After(current.ScoreDate) {
		return EPSSReplaceResult{Rows: int(current.RowCount)}, nil
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EPSSReplaceResult{}, fmt.Errorf("read epss catalog: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return EPSSReplaceResult{}, fmt.Errorf("begin epss tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	queries := q.db.WithTx(tx)
	if err := queries.ClearEPSSScores(ctx); err != nil {
		return EPSSReplaceResult{}, fmt.Errorf("clear epss: %w", err)
	}
	const batch = 10_000
	for start := 0; start < len(catalog.Scores); start += batch {
		end := min(start+batch, len(catalog.Scores))
		params := dbgen.InsertEPSSScoresParams{
			CveIds:      make([]string, 0, end-start),
			Scores:      make([]string, 0, end-start),
			Percentiles: make([]string, 0, end-start),
		}
		for _, score := range catalog.Scores[start:end] {
			params.CveIds = append(params.CveIds, score.CVEID)
			params.Scores = append(params.Scores, strconv.FormatFloat(score.Score, 'f', 5, 64))
			params.Percentiles = append(params.Percentiles, strconv.FormatFloat(score.Percentile, 'f', 5, 64))
		}
		if err := queries.InsertEPSSScores(ctx, params); err != nil {
			return EPSSReplaceResult{}, fmt.Errorf("insert epss batch: %w", err)
		}
	}
	if err := queries.SetEPSSCatalog(ctx, dbgen.SetEPSSCatalogParams{
		ModelVersion: catalog.ModelVersion,
		ScoreDate:    catalog.ScoreDate,
		RowCount:     int32(len(catalog.Scores)), // #nosec G115 -- bounded by the 64 MiB download limit
	}); err != nil {
		return EPSSReplaceResult{}, fmt.Errorf("record epss catalog: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return EPSSReplaceResult{}, fmt.Errorf("commit epss: %w", err)
	}
	return EPSSReplaceResult{Replaced: true, Rows: len(catalog.Scores)}, nil
}
