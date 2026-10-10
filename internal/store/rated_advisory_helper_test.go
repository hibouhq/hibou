package store

import (
	"context"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// upsertRatedAdvisory stores an advisory with a given headline rating, the
// way ingest's Rerate leaves it (ADR-038 §2): UpsertAdvisory no longer
// writes severity or CVSS.
func upsertRatedAdvisory(ctx context.Context, q interface {
	UpsertAdvisory(context.Context, dbgen.UpsertAdvisoryParams) (dbgen.Advisory, error)
	SetAdvisoryRating(context.Context, dbgen.SetAdvisoryRatingParams) (dbgen.Advisory, error)
}, params dbgen.UpsertAdvisoryParams, rating dbgen.SetAdvisoryRatingParams) (dbgen.Advisory, error) {
	advisory, err := q.UpsertAdvisory(ctx, params)
	if err != nil {
		return advisory, err
	}
	rating.AdvisoryID = advisory.ID
	return q.SetAdvisoryRating(ctx, rating)
}
