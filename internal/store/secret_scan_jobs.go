package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Secret scan job modes and statuses. Mirrored by CHECK constraints in
// migration 00005.
const (
	SecretScanModeFull        = "full"
	SecretScanModeIncremental = "incremental"

	SecretScanStatusPending    = "pending"
	SecretScanStatusProcessing = "processing"
	SecretScanStatusComplete   = "complete"
	SecretScanStatusFailed     = "failed"
)

type SecretScanJob struct {
	ID             uuid.UUID  `json:"id"`
	RepoID         uuid.UUID  `json:"repo_id"`
	RefName        string     `json:"ref_name"`
	Mode           string     `json:"mode"`
	FromCommit     string     `json:"from_commit,omitempty"`
	ToCommit       string     `json:"to_commit,omitempty"`
	SnapshotID     *uuid.UUID `json:"snapshot_id,omitempty"`
	Status         string     `json:"status"`
	ClaimedBy      *string    `json:"claimed_by,omitempty"`
	ClaimExpiresAt *time.Time `json:"claim_expires_at,omitempty"`
	Attempts       int32      `json:"attempts"`
	LastError      string     `json:"last_error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

type EnqueueSecretScanJobParams struct {
	RepoID     uuid.UUID
	RefName    string
	Mode       string
	FromCommit string
	ToCommit   string
	SnapshotID *uuid.UUID
}

// EnqueueSecretScanJob is safe to call on every push: a pending job for the same
// (repo, ref, mode) absorbs the new range instead of queueing another clone.
func (q *Queries) EnqueueSecretScanJob(ctx context.Context, params EnqueueSecretScanJobParams) (*SecretScanJob, error) {
	row, err := q.db.EnqueueSecretScanJob(ctx, dbgen.EnqueueSecretScanJobParams{
		RepoID:     params.RepoID,
		RefName:    params.RefName,
		Mode:       params.Mode,
		FromCommit: params.FromCommit,
		ToCommit:   params.ToCommit,
		SnapshotID: nullUUIDFromPtr(params.SnapshotID),
	})
	if err != nil {
		return nil, err
	}

	return secretScanJobFromRow(row), nil
}

// ClaimNextSecretScanJob returns nil when the queue is empty.
func (q *Queries) ClaimNextSecretScanJob(ctx context.Context, workerID string, claimExpiresAt time.Time, maxAttempts int32) (*SecretScanJob, error) {
	row, err := q.db.ClaimNextSecretScanJob(ctx, dbgen.ClaimNextSecretScanJobParams{
		MaxAttempts: maxAttempts,
		WorkerID:    sql.NullString{String: workerID, Valid: workerID != ""},
		ClaimExpiresAt: sql.NullTime{
			Time:  claimExpiresAt,
			Valid: !claimExpiresAt.IsZero(),
		},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretScanJobFromRow(row), nil
}

// RenewSecretScanJobClaim reports whether this worker still owns the job. False
// means another replica reclaimed it and the caller must abandon its work.
func (q *Queries) RenewSecretScanJobClaim(ctx context.Context, jobID uuid.UUID, workerID string, claimExpiresAt time.Time) (bool, error) {
	rows, err := q.db.RenewSecretScanJobClaim(ctx, dbgen.RenewSecretScanJobClaimParams{
		JobID:    jobID,
		WorkerID: sql.NullString{String: workerID, Valid: workerID != ""},
		ClaimExpiresAt: sql.NullTime{
			Time:  claimExpiresAt,
			Valid: !claimExpiresAt.IsZero(),
		},
	})
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

// CompleteSecretScanJob returns nil when the claim was lost, so the caller can
// tell "finalized" from "someone else owns this now".
func (q *Queries) CompleteSecretScanJob(ctx context.Context, jobID uuid.UUID, workerID string) (*SecretScanJob, error) {
	row, err := q.db.CompleteSecretScanJob(ctx, dbgen.CompleteSecretScanJobParams{
		JobID:    jobID,
		WorkerID: sql.NullString{String: workerID, Valid: workerID != ""},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretScanJobFromRow(row), nil
}

// FailSecretScanJob records the error. markFinished=false leaves the row
// claimable so another worker retries until attempts hits the cap.
func (q *Queries) FailSecretScanJob(ctx context.Context, jobID uuid.UUID, workerID, lastError string, markFinished bool) (*SecretScanJob, error) {
	row, err := q.db.FailSecretScanJob(ctx, dbgen.FailSecretScanJobParams{
		JobID:        jobID,
		WorkerID:     sql.NullString{String: workerID, Valid: workerID != ""},
		LastError:    lastError,
		MarkFinished: markFinished,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretScanJobFromRow(row), nil
}

// ReleaseSecretScanJobClaims hands unfinished work back on shutdown so a rolling
// restart doesn't wait out every lease.
func (q *Queries) ReleaseSecretScanJobClaims(ctx context.Context, workerID string) (int64, error) {
	return q.db.ReleaseSecretScanJobClaims(ctx, sql.NullString{String: workerID, Valid: workerID != ""})
}

func (q *Queries) GetSecretScanJob(ctx context.Context, id uuid.UUID) (*SecretScanJob, error) {
	row, err := q.db.GetSecretScanJob(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretScanJobFromRow(row), nil
}

// CountPendingSecretScanJobs is the queue-depth autoscaling signal.
func (q *Queries) CountPendingSecretScanJobs(ctx context.Context) (int64, error) {
	return q.db.CountPendingSecretScanJobs(ctx)
}

func (q *Queries) ListSecretScanJobsByRepo(ctx context.Context, repoID uuid.UUID, limit int32) ([]*SecretScanJob, error) {
	rows, err := q.db.ListSecretScanJobsByRepo(ctx, dbgen.ListSecretScanJobsByRepoParams{
		RepoID: repoID,
		Limit:  limit,
	})
	if err != nil {
		return nil, err
	}

	jobs := make([]*SecretScanJob, 0, len(rows))
	for _, row := range rows {
		jobs = append(jobs, secretScanJobFromRow(row))
	}

	return jobs, nil
}

func secretScanJobFromRow(row dbgen.SecretScanJob) *SecretScanJob {
	job := &SecretScanJob{
		ID:         row.ID,
		RepoID:     row.RepoID,
		RefName:    row.RefName,
		Mode:       row.Mode,
		FromCommit: row.FromCommit,
		ToCommit:   row.ToCommit,
		Status:     row.Status,
		Attempts:   row.Attempts,
		LastError:  row.LastError,
		CreatedAt:  row.CreatedAt,
	}
	if row.SnapshotID.Valid {
		id := row.SnapshotID.UUID
		job.SnapshotID = &id
	}
	if row.ClaimedBy.Valid {
		owner := row.ClaimedBy.String
		job.ClaimedBy = &owner
	}
	if row.ClaimExpiresAt.Valid {
		at := row.ClaimExpiresAt.Time
		job.ClaimExpiresAt = &at
	}
	if row.StartedAt.Valid {
		at := row.StartedAt.Time
		job.StartedAt = &at
	}
	if row.FinishedAt.Valid {
		at := row.FinishedAt.Time
		job.FinishedAt = &at
	}

	return job
}
