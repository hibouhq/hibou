package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
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
	ID             uuid.UUID      `json:"id"`
	RefID          uuid.UUID      `json:"ref_id"`
	CommitSHA      string         `json:"commit_sha"`
	Status         SnapshotStatus `json:"status"`
	Labels         []string       `json:"labels,omitempty"`
	Pinned         bool           `json:"pinned"`
	RetentionHold  bool           `json:"retention_hold"`
	ArtifactBytes  int64          `json:"artifact_bytes"`
	BuildURL       *string        `json:"build_url,omitempty"`
	RunID          *string        `json:"run_id,omitempty"`
	RunAttempt     *string        `json:"run_attempt,omitempty"`
	RunNumber      *string        `json:"run_number,omitempty"`
	PRNumber       *string        `json:"pr_number,omitempty"`
	PRTargetBranch *string        `json:"pr_target_branch,omitempty"`
	Tag            *string        `json:"tag,omitempty"`
	// What CI actually built on a pull_request event (PLAN §2): CommitSHA is
	// the developer's head commit; MergeCommitSHA the ephemeral merge commit
	// checked out; BaseCommitSHA the base-branch commit that merge used.
	MergeCommitSHA                   string     `json:"merge_commit_sha,omitempty"`
	BaseCommitSHA                    string     `json:"base_commit_sha,omitempty"`
	ExpectedUploads                  *int       `json:"expected_uploads,omitempty"`
	ReceivedUploads                  int        `json:"received_uploads"`
	ArtifactProcessingClaimedBy      *string    `json:"artifact_processing_claimed_by,omitempty"`
	ArtifactProcessingClaimExpiresAt *time.Time `json:"artifact_processing_claim_expires_at,omitempty"`
	ArtifactProcessingStartedAt      *time.Time `json:"artifact_processing_started_at,omitempty"`
	ArtifactProcessingFinishedAt     *time.Time `json:"artifact_processing_finished_at,omitempty"`
	ArtifactProcessingAttempts       int        `json:"artifact_processing_attempts"`
	ArtifactProcessingLastError      *string    `json:"artifact_processing_last_error,omitempty"`
	CreatedAt                        time.Time  `json:"created_at"`
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
	// Commit provenance (PLAN §2): the ephemeral merge commit CI actually
	// built, and the base commit that merge used. Empty for branch/tag builds.
	MergeCommitSHA string
	BaseCommitSHA  string
}

var ErrSnapshotNotCompletable = errors.New("snapshot already finalized or timed out")
var ErrArtifactProcessingClaimLost = errors.New("artifact processing claim lost")

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
		Limit:  int32(limit),  // #nosec G115 -- pagination values are bounded by API parsing.
		Offset: int32(offset), // #nosec G115 -- pagination values are bounded by API parsing.
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

func (q *Queries) ListSnapshotsForRetentionTimeline(ctx context.Context, repoID, refID uuid.UUID) ([]Snapshot, error) {
	rows, err := q.db.ListSnapshotsForRetentionTimeline(ctx, dbgen.ListSnapshotsForRetentionTimelineParams{
		RepoID: repoID,
		RefID:  refID,
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

// RepoHasUploadActivity reports whether any snapshot of the repo ever
// received a CI upload.
func (q *Queries) RepoHasUploadActivity(ctx context.Context, repoID uuid.UUID) (bool, error) {
	return q.db.RepoHasUploadActivity(ctx, repoID)
}

// CreatePlaceholderSnapshot inserts a pending snapshot for a webhook-observed
// PR head that has no snapshot yet. Returns nil (no error) when any snapshot
// already exists for the (ref, commit) pair.
func (q *Queries) CreatePlaceholderSnapshot(ctx context.Context, refID uuid.UUID, commitSHA string) (*Snapshot, error) {
	row, err := q.db.CreatePlaceholderSnapshot(ctx, dbgen.CreatePlaceholderSnapshotParams{
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

func (q *Queries) UpsertSnapshotForBuild(ctx context.Context, refID uuid.UUID, commitSHA string, status SnapshotStatus, meta SnapshotBuildMeta) (*Snapshot, error) {
	// A webhook may have pre-created a placeholder (pending, run_id NULL) for
	// this head. A CI build carrying a run_id would not hit the upsert's
	// conflict key, so it adopts the placeholder first to avoid a duplicate.
	if meta.RunID != nil && strings.TrimSpace(*meta.RunID) != "" {
		row, err := q.db.AdoptPlaceholderSnapshot(ctx, dbgen.AdoptPlaceholderSnapshotParams{
			RefID:           refID,
			CommitSha:       commitSHA,
			BuildUrl:        nullStringFromPtr(meta.BuildURL),
			RunID:           nullStringFromPtr(meta.RunID),
			RunAttempt:      nullStringFromPtr(meta.RunAttempt),
			RunNumber:       nullStringFromPtr(meta.RunNumber),
			PrNumber:        nullStringFromPtr(meta.PRNumber),
			PrTargetBranch:  nullStringFromPtr(meta.PRTargetBranch),
			Tag:             nullStringFromPtr(meta.Tag),
			ExpectedUploads: nullInt32FromPtr(meta.ExpectedUploads),
		})
		if err == nil {
			return snapshotFromRow(row), nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

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
		MergeCommitSha:  strings.TrimSpace(meta.MergeCommitSHA),
		BaseCommitSha:   strings.TrimSpace(meta.BaseCommitSHA),
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

func (q *Queries) AddSnapshotArtifactBytes(ctx context.Context, snapshotID uuid.UUID, deltaBytes int64) error {
	return q.db.AddSnapshotArtifactBytes(ctx, dbgen.AddSnapshotArtifactBytesParams{
		ID:                     snapshotID,
		RetentionArtifactBytes: deltaBytes,
	})
}

func (q *Queries) LockSnapshotForUpdate(ctx context.Context, snapshotID uuid.UUID) error {
	_, err := q.db.LockSnapshotForUpdate(ctx, snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
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

func (q *Queries) ClaimNextArtifactProcessingSnapshot(ctx context.Context, workerID string, claimExpiresAt time.Time, maxAttempts int32) (*Snapshot, error) {
	row, err := q.db.ClaimNextArtifactProcessingSnapshot(ctx, dbgen.ClaimNextArtifactProcessingSnapshotParams{
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

	return snapshotFromRow(row), nil
}

// FailPendingSnapshotsForBuild fails snapshots whose build ended without them.
func (q *Queries) FailPendingSnapshotsForBuild(ctx context.Context, repoID uuid.UUID, commitSHA, runID string) (int64, error) {
	return q.db.FailPendingSnapshotsForBuild(ctx, dbgen.FailPendingSnapshotsForBuildParams{
		RepoID:    repoID,
		CommitSha: commitSHA,
		RunID:     runID,
	})
}

// FinalizeUnreachableArtifactProcessing records snapshots as failed when they
// are stuck in 'processing' and can no longer be claimed. Returns how many.
func (q *Queries) FinalizeUnreachableArtifactProcessing(ctx context.Context, maxAttempts int32) (int64, error) {
	return q.db.FinalizeUnreachableArtifactProcessing(ctx, maxAttempts)
}

func (q *Queries) CompleteArtifactProcessingSnapshot(ctx context.Context, snapshotID uuid.UUID, workerID string) (*Snapshot, error) {
	row, err := q.db.CompleteArtifactProcessingSnapshot(ctx, dbgen.CompleteArtifactProcessingSnapshotParams{
		SnapshotID: snapshotID,
		WorkerID:   sql.NullString{String: workerID, Valid: workerID != ""},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) CompleteArtifactProcessingSnapshotWithWarning(ctx context.Context, snapshotID uuid.UUID, workerID, lastError string) (*Snapshot, error) {
	row, err := q.db.CompleteArtifactProcessingSnapshotWithWarning(ctx, dbgen.CompleteArtifactProcessingSnapshotWithWarningParams{
		SnapshotID: snapshotID,
		WorkerID:   sql.NullString{String: workerID, Valid: workerID != ""},
		LastError:  sql.NullString{String: lastError, Valid: lastError != ""},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) RenewArtifactProcessingSnapshotClaim(ctx context.Context, snapshotID uuid.UUID, workerID string, claimExpiresAt time.Time) (int64, error) {
	return q.db.RenewArtifactProcessingSnapshotClaim(ctx, dbgen.RenewArtifactProcessingSnapshotClaimParams{
		SnapshotID: snapshotID,
		WorkerID:   sql.NullString{String: workerID, Valid: workerID != ""},
		ClaimExpiresAt: sql.NullTime{
			Time:  claimExpiresAt,
			Valid: !claimExpiresAt.IsZero(),
		},
	})
}

func (q *Queries) FailArtifactProcessingSnapshot(ctx context.Context, snapshotID uuid.UUID, workerID string, markFinished bool, lastError string) (*Snapshot, error) {
	row, err := q.db.FailArtifactProcessingSnapshot(ctx, dbgen.FailArtifactProcessingSnapshotParams{
		SnapshotID:   snapshotID,
		WorkerID:     sql.NullString{String: workerID, Valid: workerID != ""},
		MarkFinished: markFinished,
		LastError:    sql.NullString{String: lastError, Valid: lastError != ""},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) ReleaseArtifactProcessingClaims(ctx context.Context, workerID string) (int64, error) {
	return q.db.ReleaseArtifactProcessingClaims(ctx, sql.NullString{String: workerID, Valid: workerID != ""})
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

func (q *Queries) GetLatestNonPurgedSnapshotByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	const query = `
		SELECT
			id,
			ref_id,
			commit_sha,
			status,
			labels,
			image_digest,
			created_at,
			build_url,
			run_id,
			run_number,
			pr_number,
			pr_target_branch,
			tag,
			expected_uploads,
			received_uploads,
			run_attempt,
			pinned,
			retention_hold,
			artifact_bytes
		FROM snapshots s
		WHERE s.ref_id = $1
		  AND s.status != 'purged'
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1
	`

	return q.getSnapshotByRefLookup(ctx, query, refID)
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

func (q *Queries) GetLatestSnapshotWithAnalysisDataByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	const query = `
		SELECT
			id,
			ref_id,
			commit_sha,
			status,
			labels,
			image_digest,
			created_at,
			build_url,
			run_id,
			run_number,
			pr_number,
			pr_target_branch,
			tag,
			expected_uploads,
			received_uploads,
			run_attempt,
			pinned,
			retention_hold,
			artifact_bytes
		FROM snapshots s
		WHERE s.ref_id = $1
		  AND s.status != 'purged'
		  AND (
			s.inventory_set_id IS NOT NULL
			OR EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.snapshot_id = s.id)
		  )
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1
	`

	var row dbgen.Snapshot
	err := q.sqlDB.QueryRowContext(ctx, query, refID).Scan(
		&row.ID,
		&row.RefID,
		&row.CommitSha,
		&row.Status,
		&row.Labels,
		&row.ImageDigest,
		&row.CreatedAt,
		&row.BuildUrl,
		&row.RunID,
		&row.RunNumber,
		&row.PrNumber,
		&row.PrTargetBranch,
		&row.Tag,
		&row.ExpectedUploads,
		&row.ReceivedUploads,
		&row.RunAttempt,
		&row.Pinned,
		&row.RetentionHold,
		&row.ArtifactBytes,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetLatestSnapshotWithComponentsByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	const query = `
		SELECT
			id,
			ref_id,
			commit_sha,
			status,
			labels,
			image_digest,
			created_at,
			build_url,
			run_id,
			run_number,
			pr_number,
			pr_target_branch,
			tag,
			expected_uploads,
			received_uploads,
			run_attempt,
			pinned,
			retention_hold,
			artifact_bytes
		FROM snapshots s
		WHERE s.ref_id = $1
		  AND s.status != 'purged'
		  AND s.inventory_set_id IS NOT NULL
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1
	`

	return q.getSnapshotByRefLookup(ctx, query, refID)
}

func (q *Queries) GetLatestSnapshotWithVulnerabilitiesByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	const query = `
		SELECT
			id,
			ref_id,
			commit_sha,
			status,
			labels,
			image_digest,
			created_at,
			build_url,
			run_id,
			run_number,
			pr_number,
			pr_target_branch,
			tag,
			expected_uploads,
			received_uploads,
			run_attempt,
			pinned,
			retention_hold,
			artifact_bytes
		FROM snapshots s
		WHERE s.ref_id = $1
		  AND s.status != 'purged'
		  AND EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.snapshot_id = s.id)
		ORDER BY s.created_at DESC, s.id DESC
		LIMIT 1
	`

	return q.getSnapshotByRefLookup(ctx, query, refID)
}

func (q *Queries) getSnapshotByRefLookup(ctx context.Context, query string, refID uuid.UUID) (*Snapshot, error) {
	var row dbgen.Snapshot
	err := q.sqlDB.QueryRowContext(ctx, query, refID).Scan(
		&row.ID,
		&row.RefID,
		&row.CommitSha,
		&row.Status,
		&row.Labels,
		&row.ImageDigest,
		&row.CreatedAt,
		&row.BuildUrl,
		&row.RunID,
		&row.RunNumber,
		&row.PrNumber,
		&row.PrTargetBranch,
		&row.Tag,
		&row.ExpectedUploads,
		&row.ReceivedUploads,
		&row.RunAttempt,
		&row.Pinned,
		&row.RetentionHold,
		&row.ArtifactBytes,
	)
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

func (q *Queries) ListStalePendingSnapshots(ctx context.Context, startedBefore, placeholderBefore time.Time, limit int32) ([]Snapshot, error) {
	rows, err := q.db.ListStalePendingSnapshots(ctx, dbgen.ListStalePendingSnapshotsParams{
		StartedBefore:     startedBefore,
		PlaceholderBefore: placeholderBefore,
		RowLimit:          limit,
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

func (q *Queries) UpdateSnapshotRetentionFlags(ctx context.Context, id uuid.UUID, pinned, retentionHold bool) (*Snapshot, error) {
	row, err := q.db.UpdateSnapshotRetentionFlags(ctx, dbgen.UpdateSnapshotRetentionFlagsParams{
		ID:            id,
		Pinned:        pinned,
		RetentionHold: retentionHold,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func snapshotFromRow(row dbgen.Snapshot) *Snapshot {
	var expectedUploads *int
	if row.ExpectedUploads.Valid {
		value := int(row.ExpectedUploads.Int32)
		expectedUploads = &value
	}

	return &Snapshot{
		ID:                               row.ID,
		RefID:                            row.RefID,
		CommitSHA:                        row.CommitSha,
		Status:                           row.Status,
		Labels:                           parseSnapshotLabels(row.Labels),
		Pinned:                           row.Pinned,
		RetentionHold:                    row.RetentionHold,
		ArtifactBytes:                    row.ArtifactBytes,
		BuildURL:                         stringPtrFromNull(row.BuildUrl),
		RunID:                            stringPtrFromNull(row.RunID),
		RunAttempt:                       stringPtrFromNull(row.RunAttempt),
		RunNumber:                        stringPtrFromNull(row.RunNumber),
		PRNumber:                         stringPtrFromNull(row.PrNumber),
		PRTargetBranch:                   stringPtrFromNull(row.PrTargetBranch),
		Tag:                              stringPtrFromNull(row.Tag),
		MergeCommitSHA:                   row.MergeCommitSha,
		BaseCommitSHA:                    row.BaseCommitSha,
		ExpectedUploads:                  expectedUploads,
		ReceivedUploads:                  int(row.ReceivedUploads),
		ArtifactProcessingClaimedBy:      stringPtrFromNull(row.ArtifactProcessingClaimedBy),
		ArtifactProcessingClaimExpiresAt: timePtrFromNull(row.ArtifactProcessingClaimExpiresAt),
		ArtifactProcessingStartedAt:      timePtrFromNull(row.ArtifactProcessingStartedAt),
		ArtifactProcessingFinishedAt:     timePtrFromNull(row.ArtifactProcessingFinishedAt),
		ArtifactProcessingAttempts:       int(row.ArtifactProcessingAttempts),
		ArtifactProcessingLastError:      stringPtrFromNull(row.ArtifactProcessingLastError),
		CreatedAt:                        row.CreatedAt,
	}
}

func parseSnapshotLabels(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var labels []string
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil
	}
	return labels
}

// GetSnapshotRowByRefCommit returns the raw snapshot row at an exact
// (ref, commit) — the gate publisher's base-provenance lookup (PLAN §2/§5).
// sql.ErrNoRows when that base snapshot no longer exists.
func (q *Queries) GetSnapshotRowByRefCommit(ctx context.Context, refID uuid.UUID, commitSHA string) (dbgen.Snapshot, error) {
	return q.db.GetSnapshotByRefCommit(ctx, dbgen.GetSnapshotByRefCommitParams{RefID: refID, CommitSha: commitSHA})
}
