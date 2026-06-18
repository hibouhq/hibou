package retention

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

const batchSize int32 = 100

type Worker struct {
	store         WorkerStore
	objStore      objstore.Store
	log           zerolog.Logger
	policy        Policy
	pendingWindow time.Duration
}

type WorkerStore interface {
	ListExpiredSnapshots(ctx context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error)
	ListStalePendingSnapshots(ctx context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error)
	ListSnapshotArtifactObjectKeys(ctx context.Context, snapshotID uuid.UUID) ([]string, error)
	ArchiveSnapshot(ctx context.Context, id uuid.UUID) error
	MarkSnapshotFailed(ctx context.Context, id uuid.UUID) error
	PurgeSnapshot(ctx context.Context, id uuid.UUID) error
}

type archivedSnapshotStore interface {
	ListArchivedSnapshotsForPurge(ctx context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error)
}

func NewWorker(store WorkerStore, objStore objstore.Store, log zerolog.Logger, policy Policy, pendingWindow time.Duration) *Worker {
	return &Worker{store: store, objStore: objStore, log: log, policy: policy, pendingWindow: pendingWindow}
}

func (w *Worker) Run(ctx context.Context) error {
	if w.store == nil {
		return nil
	}

	hotCutoff := time.Now().Add(-w.policy.HotRetention)
	expired, err := w.store.ListExpiredSnapshots(ctx, hotCutoff, batchSize)
	if err != nil {
		return err
	}
	for _, snapshot := range expired {
		if err := w.store.ArchiveSnapshot(ctx, snapshot.ID); err != nil {
			return err
		}
		w.log.Info().Str("snapshot_id", snapshot.ID.String()).Msg("archived snapshot")
	}

	if !w.policy.AutoPurge {
		return nil
	}
	if w.objStore == nil {
		return nil
	}

	archiveCutoff := time.Now().Add(-w.policy.ArchiveRetention)
	archived, err := w.listArchivedSnapshots(ctx, archiveCutoff)
	if err != nil {
		return err
	}
	for _, snapshot := range archived {
		keys, err := w.store.ListSnapshotArtifactObjectKeys(ctx, snapshot.ID)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := w.deleteArtifact(ctx, key); err != nil {
				return err
			}
		}
		if err := w.store.PurgeSnapshot(ctx, snapshot.ID); err != nil {
			return err
		}
		w.log.Info().Str("snapshot_id", snapshot.ID.String()).Msg("purged snapshot")
	}

	return nil
}

func (w *Worker) SweepStalePending(ctx context.Context) error {
	if w.store == nil || w.pendingWindow <= 0 {
		return nil
	}

	cutoff := time.Now().Add(-w.pendingWindow)
	staleSnapshots, err := w.store.ListStalePendingSnapshots(ctx, cutoff, batchSize)
	if err != nil {
		return err
	}
	for _, snapshot := range staleSnapshots {
		if err := w.store.MarkSnapshotFailed(ctx, snapshot.ID); err != nil {
			return err
		}
		w.log.Info().Str("snapshot_id", snapshot.ID.String()).Msg("failed stale pending snapshot")
	}

	return nil
}

func (w *Worker) listArchivedSnapshots(ctx context.Context, before time.Time) ([]dbgen.Snapshot, error) {
	if store, ok := w.store.(archivedSnapshotStore); ok {
		return store.ListArchivedSnapshotsForPurge(ctx, before, batchSize)
	}
	rows, err := w.store.ListExpiredSnapshots(ctx, before, batchSize)
	if err != nil {
		return nil, err
	}
	filtered := make([]dbgen.Snapshot, 0, len(rows))
	for _, row := range rows {
		if row.Status == dbgen.SnapshotStatusArchived {
			filtered = append(filtered, row)
		}
	}
	return filtered, nil
}

func (w *Worker) deleteArtifact(ctx context.Context, key string) error {
	if w.objStore == nil || key == "" {
		return nil
	}
	if err := w.objStore.Delete(ctx, key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
