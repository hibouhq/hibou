package retention

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) ListExpiredSnapshots(ctx context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error) {
	rows, err := a.queries.ListExpiredSnapshots(ctx, before, limit)
	if err != nil {
		return nil, err
	}
	return snapshotsToRows(rows), nil
}

func (a *StoreAdapter) ListArchivedSnapshotsForPurge(ctx context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error) {
	rows, err := a.queries.ListArchivedSnapshotsForPurge(ctx, before, limit)
	if err != nil {
		return nil, err
	}
	return snapshotsToRows(rows), nil
}

func (a *StoreAdapter) ArchiveSnapshot(ctx context.Context, id uuid.UUID) error {
	return a.queries.ArchiveSnapshot(ctx, id)
}

func (a *StoreAdapter) PurgeSnapshot(ctx context.Context, id uuid.UUID) error {
	return a.queries.PurgeSnapshot(ctx, id)
}

func snapshotsToRows(rows []store.Snapshot) []dbgen.Snapshot {
	result := make([]dbgen.Snapshot, 0, len(rows))
	for _, row := range rows {
		result = append(result, dbgen.Snapshot{
			ID:             row.ID,
			RefID:          row.RefID,
			CommitSha:      row.CommitSHA,
			Label:          stringToNull(row.Label),
			Status:         row.Status,
			RawArtifactUrl: stringToNull(row.RawArtifactURL),
			CreatedAt:      row.CreatedAt,
			ArtifactKey:    row.ArtifactKey,
		})
	}
	return result
}

func stringToNull(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}
