package retention

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) ListStalePendingSnapshots(ctx context.Context, startedBefore, placeholderBefore time.Time, limit int32) ([]dbgen.Snapshot, error) {
	rows, err := a.queries.ListStalePendingSnapshots(ctx, startedBefore, placeholderBefore, limit)
	if err != nil {
		return nil, err
	}
	return snapshotsToRows(rows), nil
}

func (a *StoreAdapter) ListRepositoriesForRetention(ctx context.Context) ([]store.Repository, error) {
	return a.queries.ListRepositoriesForRetention(ctx)
}

func (a *StoreAdapter) ListRefsByRepo(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]store.Ref, int, error) {
	return a.queries.ListRefsByRepo(ctx, repoID, limit, offset)
}

func (a *StoreAdapter) ListSnapshotsForRetentionTimeline(ctx context.Context, repoID, refID uuid.UUID) ([]store.Snapshot, error) {
	return a.queries.ListSnapshotsForRetentionTimeline(ctx, repoID, refID)
}

func (a *StoreAdapter) ListVulnerabilitySummaryBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListVulnerabilitySummaryBySnapshotRow, error) {
	return a.queries.ListVulnerabilitySummaryBySnapshot(ctx, snapshotID)
}

func (a *StoreAdapter) ListSnapshotArtifactObjectKeys(ctx context.Context, snapshotID uuid.UUID) ([]string, error) {
	return a.queries.ListSnapshotArtifactObjectKeys(ctx, snapshotID)
}

func (a *StoreAdapter) ArchiveSnapshot(ctx context.Context, id uuid.UUID) error {
	return a.queries.ArchiveSnapshot(ctx, id)
}

func (a *StoreAdapter) PurgeSnapshot(ctx context.Context, id uuid.UUID) error {
	// Drop cached forge comparisons involving this commit before the snapshot
	// goes: they are keyed by commit SHA, so nothing else would ever clean them
	// up (ADR-019 — the cache has no TTL by design).
	a.purgeComparePatchCache(ctx, id)
	return a.queries.PurgeSnapshot(ctx, id)
}

// purgeComparePatchCache is best-effort: a stale cache row is harmless (the
// comparison is unreachable once the snapshot is gone), so a failure here must
// never block the purge itself.
func (a *StoreAdapter) purgeComparePatchCache(ctx context.Context, snapshotID uuid.UUID) {
	snapshot, err := a.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil || snapshot.CommitSHA == "" {
		return
	}
	ref, err := a.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return
	}
	_ = a.queries.DeleteComparePatchCacheForCommit(ctx, ref.RepoID, snapshot.CommitSHA)
}

func (a *StoreAdapter) MarkSnapshotFailed(ctx context.Context, id uuid.UUID) error {
	_, err := a.queries.MarkSnapshotFailedIfPending(ctx, id)
	return err
}

func (a *StoreAdapter) RollupSnapshotVulnerabilities(ctx context.Context, snapshotID uuid.UUID) (int64, error) {
	return a.queries.RollupSnapshotVulnerabilities(ctx, snapshotID)
}

func (a *StoreAdapter) GetSnapshotVulnRollup(ctx context.Context, snapshotID uuid.UUID) (store.SnapshotVulnRollup, bool, error) {
	return a.queries.GetSnapshotVulnRollup(ctx, snapshotID)
}

func snapshotsToRows(rows []store.Snapshot) []dbgen.Snapshot {
	result := make([]dbgen.Snapshot, 0, len(rows))
	for _, row := range rows {
		result = append(result, dbgen.Snapshot{
			ID:        row.ID,
			RefID:     row.RefID,
			CommitSha: row.CommitSHA,
			Status:    row.Status,
			CreatedAt: row.CreatedAt,
		})
	}
	return result
}
