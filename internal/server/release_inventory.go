package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

var (
	errReleaseInventoryNotNeeded = errors.New("release already has inventory or no supported extraction is needed")
	errReleaseInventoryConflict  = errors.New("another extraction targets a different pinned snapshot of this tag; retry after it finishes")
)

func (s *Server) queueReleaseInventory(ctx context.Context, repo *store.Repository, releaseID uuid.UUID) (*store.DepExtractionJob, bool, error) {
	tx, err := s.queries.BeginTx(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	if _, err := tx.ExecContext(ctx, `SELECT id FROM repositories WHERE id=$1 FOR UPDATE`, repo.ID); err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT id FROM releases WHERE id=$1 AND repo_id=$2 FOR UPDATE`, releaseID, repo.ID); err != nil {
		return nil, false, err
	}
	release, err := q.GetReleaseByRepoAndID(ctx, repo.ID, releaseID)
	if err != nil {
		return nil, false, err
	}
	if release == nil {
		return nil, false, errors.New("release no longer exists in this repository")
	}
	statuses, err := q.ListReleaseInventories(ctx, repo.ID, []uuid.UUID{release.ID})
	if err != nil {
		return nil, false, err
	}
	status := statuses[release.ID]
	if !status.CanExtract {
		if (status.State == "queued" || status.State == "processing") && status.JobID != nil {
			job, err := q.GetDepExtractionJob(ctx, *status.JobID)
			return job, false, err
		}
		return nil, false, errReleaseInventoryNotNeeded
	}
	ref, err := q.GetRefByID(ctx, release.RefID)
	if err != nil {
		return nil, false, err
	}
	if ref == nil || ref.RepoID != repo.ID || ref.RefType != store.RefTypeTag {
		return nil, false, errors.New("release has no valid tag ref to extract")
	}
	params := store.EnqueueDepExtractionJobParams{
		RepoID: repo.ID, RefName: "refs/tags/" + normalizeStoredRefName(ref.Name),
		Reason: store.DepExtractionReasonRelease, SnapshotID: release.SnapshotID,
	}
	if release.SnapshotID != nil {
		snapshot, err := q.GetSnapshotByID(ctx, *release.SnapshotID)
		if err != nil {
			return nil, false, err
		}
		if snapshot == nil || snapshot.RefID != ref.ID {
			return nil, false, errors.New("release snapshot does not match its enrolled repository and tag")
		}
		params.CommitSHA = snapshot.CommitSHA
	} else if ref.LatestCommitSHA != nil {
		params.CommitSHA = *ref.LatestCommitSHA
	}
	latest, err := q.GetLatestDepExtractionJobForRef(ctx, repo.ID, params.RefName)
	if err != nil {
		return nil, false, err
	}
	sameSnapshot := latest == nil || latest.SnapshotID == nil && params.SnapshotID == nil ||
		latest.SnapshotID != nil && params.SnapshotID != nil && *latest.SnapshotID == *params.SnapshotID
	if latest != nil && (latest.Status == "pending" || latest.Status == "processing" ||
		latest.Status == "failed" && latest.FinishedAt == nil) &&
		(latest.CommitSHA != params.CommitSHA || !sameSnapshot) {
		return nil, false, errReleaseInventoryConflict
	}
	job, queued, err := q.EnqueueSCAExtraction(ctx, params)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return job, queued, nil
}

func (s *Server) pinReleaseInventorySnapshot(ctx context.Context, ref *store.Ref, snapshot *store.Snapshot) error {
	tx, err := s.queries.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	attached, err := q.AttachSnapshotToReleasesByRef(ctx, ref.ID, snapshot.ID)
	if err != nil {
		return fmt.Errorf("attach extracted release snapshot: %w", err)
	}
	if attached > 0 {
		if _, err := q.UpdateSnapshotRetentionFlags(ctx, snapshot.ID, true, snapshot.RetentionHold); err != nil {
			return fmt.Errorf("pin extracted release snapshot: %w", err)
		}
	}
	return tx.Commit()
}
