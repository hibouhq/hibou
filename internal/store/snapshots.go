package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type SnapshotStatus = dbgen.SnapshotStatus

const (
	SnapshotStatusPending    = dbgen.SnapshotStatusPending
	SnapshotStatusProcessing = dbgen.SnapshotStatusProcessing
	SnapshotStatusComplete   = dbgen.SnapshotStatusComplete
	SnapshotStatusFailed     = dbgen.SnapshotStatusFailed
	SnapshotStatusActive     = dbgen.SnapshotStatusActive
	SnapshotStatusArchived   = dbgen.SnapshotStatusArchived
	SnapshotStatusPurged     = dbgen.SnapshotStatusPurged
)

type Snapshot struct {
	ID              uuid.UUID      `json:"id"`
	RefID           uuid.UUID      `json:"ref_id"`
	CommitSHA       string         `json:"commit_sha"`
	Status          SnapshotStatus `json:"status"`
	BuildURL        *string        `json:"build_url,omitempty"`
	RunID           *string        `json:"run_id,omitempty"`
	RunAttempt      *string        `json:"run_attempt,omitempty"`
	RunNumber       *string        `json:"run_number,omitempty"`
	PRNumber        *string        `json:"pr_number,omitempty"`
	PRTargetBranch  *string        `json:"pr_target_branch,omitempty"`
	Tag             *string        `json:"tag,omitempty"`
	ExpectedUploads *int           `json:"expected_uploads,omitempty"`
	ReceivedUploads int            `json:"received_uploads"`
	CreatedAt       time.Time      `json:"created_at"`
}

type SnapshotBuildMeta struct {
	BuildURL        *string
	RunID           *string
	RunAttempt      *string
	RunNumber       *string
	PRNumber        *string
	PRTargetBranch  *string
	Tag             *string
	ExpectedUploads *int32
}

var ErrSnapshotNotCompletable = errors.New("snapshot already finalized or timed out")

func (q *Queries) CreateSnapshot(ctx context.Context, refID uuid.UUID, commitSHA string, status SnapshotStatus) (*Snapshot, error) {
	row, err := q.db.CreateSnapshot(ctx, dbgen.CreateSnapshotParams{
		RefID:     refID,
		CommitSha: commitSHA,
		Status:    status,
	})
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetSnapshotByRefCommit(ctx context.Context, refID uuid.UUID, commitSHA string) (*Snapshot, error) {
	row, err := q.db.GetSnapshotByRefCommit(ctx, dbgen.GetSnapshotByRefCommitParams{
		RefID:     refID,
		CommitSha: commitSHA,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetSnapshotByBuildIdentity(ctx context.Context, refID uuid.UUID, commitSHA string, runID, runAttempt *string) (*Snapshot, error) {
	row, err := q.db.GetSnapshotByBuildIdentity(ctx, dbgen.GetSnapshotByBuildIdentityParams{
		RefID:      refID,
		CommitSha:  commitSHA,
		RunID:      nullStringFromPtr(runID),
		RunAttempt: nullStringFromPtr(runAttempt),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetLatestSnapshotForBuild(ctx context.Context, refID uuid.UUID, commitSHA string, runID *string) (*Snapshot, error) {
	row, err := q.db.GetLatestSnapshotForBuild(ctx, dbgen.GetLatestSnapshotForBuildParams{
		RefID:     refID,
		CommitSha: commitSHA,
		RunID:     nullStringFromPtr(runID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) CountSnapshotsForBuild(ctx context.Context, refID uuid.UUID, commitSHA string, runID *string) (int64, error) {
	return q.db.CountSnapshotsForBuild(ctx, dbgen.CountSnapshotsForBuildParams{
		RefID:     refID,
		CommitSha: commitSHA,
		RunID:     nullStringFromPtr(runID),
	})
}

func (q *Queries) GetSnapshotByID(ctx context.Context, id uuid.UUID) (*Snapshot, error) {
	row, err := q.db.GetSnapshotByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetSnapshotAtDate(ctx context.Context, repoID uuid.UUID, refName string, asOf time.Time) (*Snapshot, error) {
	row, err := q.db.GetSnapshotAtDate(ctx, dbgen.GetSnapshotAtDateParams{
		RepoID:    repoID,
		Name:      refName,
		CreatedAt: asOf,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) ListSnapshotsByRef(ctx context.Context, refID uuid.UUID, limit, offset int) ([]Snapshot, int, error) {
	rows, err := q.db.ListSnapshotsByRef(ctx, dbgen.ListSnapshotsByRefParams{
		RefID:  refID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	snapshots := make([]Snapshot, len(rows))
	for i, row := range rows {
		snapshots[i] = *snapshotFromRow(row)
	}

	total, err := q.db.CountSnapshotsByRef(ctx, refID)
	if err != nil {
		return nil, 0, err
	}

	return snapshots, int(total), nil
}

func (q *Queries) UpdateSnapshotStatus(ctx context.Context, id uuid.UUID, status SnapshotStatus) (*Snapshot, error) {
	row, err := q.db.UpdateSnapshotStatus(ctx, dbgen.UpdateSnapshotStatusParams{
		ID:     id,
		Status: status,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) MarkSnapshotFailedIfPending(ctx context.Context, id uuid.UUID) (int64, error) {
	return q.db.MarkSnapshotFailedIfPending(ctx, id)
}

func (q *Queries) UpsertSnapshotForBuild(ctx context.Context, refID uuid.UUID, commitSHA string, status SnapshotStatus, meta SnapshotBuildMeta) (*Snapshot, error) {
	row, err := q.db.UpsertSnapshotForBuild(ctx, dbgen.UpsertSnapshotForBuildParams{
		RefID:           refID,
		CommitSha:       commitSHA,
		Status:          status,
		BuildUrl:        nullStringFromPtr(meta.BuildURL),
		RunID:           nullStringFromPtr(meta.RunID),
		RunAttempt:      nullStringFromPtr(meta.RunAttempt),
		RunNumber:       nullStringFromPtr(meta.RunNumber),
		PrNumber:        nullStringFromPtr(meta.PRNumber),
		PrTargetBranch:  nullStringFromPtr(meta.PRTargetBranch),
		Tag:             nullStringFromPtr(meta.Tag),
		ExpectedUploads: nullInt32FromPtr(meta.ExpectedUploads),
	})
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) IncrementSnapshotReceivedUploads(ctx context.Context, id uuid.UUID) (*Snapshot, error) {
	row, err := q.db.IncrementSnapshotReceivedUploads(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) CompleteSnapshot(ctx context.Context, id uuid.UUID) (*Snapshot, error) {
	row, err := q.db.CompleteSnapshot(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSnapshotNotCompletable
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	row, err := q.db.GetLatestSnapshotByRef(ctx, refID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetLatestCompleteSnapshotByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	row, err := q.db.GetLatestCompleteSnapshotByRef(ctx, refID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) ListExpiredSnapshots(ctx context.Context, before time.Time, limit int32) ([]Snapshot, error) {
	rows, err := q.db.ListExpiredSnapshots(ctx, dbgen.ListExpiredSnapshotsParams{
		CreatedAt: before,
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}

	snapshots := make([]Snapshot, len(rows))
	for i, row := range rows {
		snapshots[i] = *snapshotFromRow(row)
	}

	return snapshots, nil
}

func (q *Queries) ListStalePendingSnapshots(ctx context.Context, before time.Time, limit int32) ([]Snapshot, error) {
	rows, err := q.db.ListStalePendingSnapshots(ctx, dbgen.ListStalePendingSnapshotsParams{
		CreatedAt: before,
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}

	snapshots := make([]Snapshot, len(rows))
	for i, row := range rows {
		snapshots[i] = *snapshotFromRow(row)
	}

	return snapshots, nil
}

func (q *Queries) ListArchivedSnapshotsForPurge(ctx context.Context, before time.Time, limit int32) ([]Snapshot, error) {
	rows, err := q.db.ListArchivedSnapshotsForPurge(ctx, dbgen.ListArchivedSnapshotsForPurgeParams{
		CreatedAt: before,
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}

	snapshots := make([]Snapshot, len(rows))
	for i, row := range rows {
		snapshots[i] = *snapshotFromRow(row)
	}

	return snapshots, nil
}

func (q *Queries) ArchiveSnapshot(ctx context.Context, id uuid.UUID) error {
	return q.db.ArchiveSnapshot(ctx, id)
}

func (q *Queries) PurgeSnapshot(ctx context.Context, id uuid.UUID) error {
	return q.db.PurgeSnapshot(ctx, id)
}

func snapshotFromRow(row dbgen.Snapshot) *Snapshot {
	var expectedUploads *int
	if row.ExpectedUploads.Valid {
		value := int(row.ExpectedUploads.Int32)
		expectedUploads = &value
	}

	return &Snapshot{
		ID:              row.ID,
		RefID:           row.RefID,
		CommitSHA:       row.CommitSha,
		Status:          row.Status,
		BuildURL:        stringPtrFromNull(row.BuildUrl),
		RunID:           stringPtrFromNull(row.RunID),
		RunAttempt:      stringPtrFromNull(row.RunAttempt),
		RunNumber:       stringPtrFromNull(row.RunNumber),
		PRNumber:        stringPtrFromNull(row.PrNumber),
		PRTargetBranch:  stringPtrFromNull(row.PrTargetBranch),
		Tag:             stringPtrFromNull(row.Tag),
		ExpectedUploads: expectedUploads,
		ReceivedUploads: int(row.ReceivedUploads),
		CreatedAt:       row.CreatedAt,
	}
}
