package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Dependency extraction jobs and runs (ADR-045 §4.1).

const (
	DepExtractionReasonPush       = "push"
	DepExtractionReasonRelease    = "release"
	DepExtractionReasonEnrollment = "enrollment"
	DepExtractionReasonManual     = "manual"
	// DepExtractionReasonLazy: a ref someone opened that had no inventory
	// yet (ADR-045 §4.1.1).
	DepExtractionReasonLazy = "lazy"
	// DepExtractionReasonUpgrade: a newer extractor re-reads the inputs of
	// eager branches and pinned releases (ADR-045 §4.3.1), additively.
	DepExtractionReasonUpgrade = "extractor_upgrade"
	// DepExtractionReasonPullRequest: a PR whose diff touches a manifest
	// (ADR-045 §4.1.2).
	DepExtractionReasonPullRequest = "pull_request"
)

type DepExtractionJob struct {
	ID             uuid.UUID  `json:"id"`
	RepoID         uuid.UUID  `json:"repo_id"`
	RefName        string     `json:"ref_name"`
	CommitSHA      string     `json:"commit_sha,omitempty"`
	Reason         string     `json:"reason"`
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

type EnqueueDepExtractionJobParams struct {
	RepoID     uuid.UUID
	RefName    string
	CommitSHA  string
	Reason     string
	SnapshotID *uuid.UUID
}

// EnqueueDepExtractionJob is safe to call on every push: a pending job for
// the same (repo, ref) absorbs the newer commit.
func (q *Queries) EnqueueDepExtractionJob(ctx context.Context, params EnqueueDepExtractionJobParams) (*DepExtractionJob, error) {
	reason := params.Reason
	if reason == "" {
		reason = DepExtractionReasonPush
	}
	row, err := q.db.EnqueueDepExtractionJob(ctx, dbgen.EnqueueDepExtractionJobParams{
		RepoID:     params.RepoID,
		RefName:    params.RefName,
		CommitSha:  params.CommitSHA,
		Reason:     reason,
		SnapshotID: nullUUIDFromPtr(params.SnapshotID),
	})
	if err != nil {
		return nil, err
	}
	return depExtractionJobFromRow(row), nil
}

// ClaimNextDepExtractionJob returns nil when the queue is empty.
func (q *Queries) ClaimNextDepExtractionJob(ctx context.Context, workerID string, claimExpiresAt time.Time, maxAttempts int32) (*DepExtractionJob, error) {
	row, err := q.db.ClaimNextDepExtractionJob(ctx, dbgen.ClaimNextDepExtractionJobParams{
		MaxAttempts:    maxAttempts,
		WorkerID:       sql.NullString{String: workerID, Valid: true},
		ClaimExpiresAt: sql.NullTime{Time: claimExpiresAt, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionJobFromRow(row), nil
}

func (q *Queries) RenewDepExtractionJobClaim(ctx context.Context, jobID uuid.UUID, workerID string, claimExpiresAt time.Time) (bool, error) {
	rows, err := q.db.RenewDepExtractionJobClaim(ctx, dbgen.RenewDepExtractionJobClaimParams{
		ClaimExpiresAt: sql.NullTime{Time: claimExpiresAt, Valid: true},
		JobID:          jobID,
		WorkerID:       sql.NullString{String: workerID, Valid: true},
	})
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (q *Queries) CompleteDepExtractionJob(ctx context.Context, jobID uuid.UUID, workerID string, snapshotID *uuid.UUID) (*DepExtractionJob, error) {
	row, err := q.db.CompleteDepExtractionJob(ctx, dbgen.CompleteDepExtractionJobParams{
		SnapshotID: nullUUIDFromPtr(snapshotID),
		JobID:      jobID,
		WorkerID:   sql.NullString{String: workerID, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionJobFromRow(row), nil
}

func (q *Queries) FailDepExtractionJob(ctx context.Context, jobID uuid.UUID, workerID, lastError string, markFinished bool) (*DepExtractionJob, error) {
	row, err := q.db.FailDepExtractionJob(ctx, dbgen.FailDepExtractionJobParams{
		MarkFinished: markFinished,
		LastError:    lastError,
		JobID:        jobID,
		WorkerID:     sql.NullString{String: workerID, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionJobFromRow(row), nil
}

func (q *Queries) ReleaseDepExtractionJobClaims(ctx context.Context, workerID string) (int64, error) {
	return q.db.ReleaseDepExtractionJobClaims(ctx, sql.NullString{String: workerID, Valid: true})
}

func (q *Queries) GetDepExtractionJob(ctx context.Context, id uuid.UUID) (*DepExtractionJob, error) {
	row, err := q.db.GetDepExtractionJob(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionJobFromRow(row), nil
}

func (q *Queries) ListDepExtractionJobsByRepo(ctx context.Context, repoID uuid.UUID, limit int32) ([]*DepExtractionJob, error) {
	rows, err := q.db.ListDepExtractionJobsByRepo(ctx, dbgen.ListDepExtractionJobsByRepoParams{RepoID: repoID, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	jobs := make([]*DepExtractionJob, 0, len(rows))
	for _, row := range rows {
		jobs = append(jobs, depExtractionJobFromRow(row))
	}
	return jobs, nil
}

// GetLatestDepExtractionJobForRef returns the newest job of a ref, nil when
// none was ever enqueued.
func (q *Queries) GetLatestDepExtractionJobForRef(ctx context.Context, repoID uuid.UUID, refName string) (*DepExtractionJob, error) {
	row, err := q.db.GetLatestDepExtractionJobForRef(ctx, dbgen.GetLatestDepExtractionJobForRefParams{RepoID: repoID, RefName: refName})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionJobFromRow(row), nil
}

func (q *Queries) CountPendingDepExtractionJobs(ctx context.Context) (int64, error) {
	return q.db.CountPendingDepExtractionJobs(ctx)
}

func depExtractionJobFromRow(row dbgen.DepExtractionJob) *DepExtractionJob {
	job := &DepExtractionJob{
		ID:        row.ID,
		RepoID:    row.RepoID,
		RefName:   row.RefName,
		CommitSHA: row.CommitSha,
		Reason:    row.Reason,
		Status:    row.Status,
		Attempts:  row.Attempts,
		LastError: row.LastError,
		CreatedAt: row.CreatedAt,
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

// DepExtractionModule is one module's completeness, stored with the run.
type DepExtractionModule struct {
	Path       string   `json:"path"`
	Files      []string `json:"files"`
	Complete   bool     `json:"complete"`
	Reason     string   `json:"reason,omitempty"`
	Ecosystems []string `json:"ecosystems"`
	// InstallConfig is the module's install-time cooldown setting per
	// package manager (ADR-048 §3.1): present or missing, and its window.
	InstallConfig []DepInstallConfig `json:"install_config,omitempty"`
}

// DepInstallConfig is one package manager's install-time cooldown setting.
type DepInstallConfig struct {
	Tool          string `json:"tool"`
	Path          string `json:"path"`
	Setting       string `json:"setting"`
	Present       bool   `json:"present"`
	WindowSeconds int64  `json:"window_seconds,omitempty"`
	Value         string `json:"value,omitempty"`
	Note          string `json:"note,omitempty"`
}

// DepUpdaterConfig is the dependency updater's cooldown (Renovate,
// Dependabot), compared with the install setting.
type DepUpdaterConfig struct {
	Tool          string `json:"tool"`
	Path          string `json:"path"`
	Present       bool   `json:"present"`
	WindowSeconds int64  `json:"window_seconds,omitempty"`
	Value         string `json:"value,omitempty"`
}

type DepExtractionRun struct {
	ID               uuid.UUID             `json:"id"`
	RepoID           uuid.UUID             `json:"repo_id"`
	SnapshotID       uuid.UUID             `json:"snapshot_id"`
	CommitSHA        string                `json:"commit_sha"`
	InputDigest      string                `json:"input_digest"`
	ExtractorVersion string                `json:"extractor_version"`
	ArtifactID       *uuid.UUID            `json:"artifact_id,omitempty"`
	ObjectKey        string                `json:"object_key"`
	SHA256           string                `json:"sha256"`
	SizeBytes        int64                 `json:"size_bytes"`
	ComponentCount   int                   `json:"component_count"`
	Modules          []DepExtractionModule `json:"modules"`
	Updaters         []DepUpdaterConfig    `json:"updaters"`
	ReusedFrom       *uuid.UUID            `json:"reused_from,omitempty"`
	CreatedAt        time.Time             `json:"created_at"`
}

type InsertDepExtractionRunParams struct {
	RepoID           uuid.UUID
	SnapshotID       uuid.UUID
	CommitSHA        string
	InputDigest      string
	ExtractorVersion string
	ArtifactID       *uuid.UUID
	ObjectKey        string
	SHA256           string
	SizeBytes        int64
	ComponentCount   int
	Modules          []DepExtractionModule
	Updaters         []DepUpdaterConfig
	ReusedFrom       *uuid.UUID
}

func (q *Queries) InsertDepExtractionRun(ctx context.Context, params InsertDepExtractionRunParams) (*DepExtractionRun, error) {
	modules := params.Modules
	if modules == nil {
		modules = []DepExtractionModule{}
	}
	encoded, err := json.Marshal(modules)
	if err != nil {
		return nil, err
	}
	updaters := params.Updaters
	if updaters == nil {
		updaters = []DepUpdaterConfig{}
	}
	encodedUpdaters, err := json.Marshal(updaters)
	if err != nil {
		return nil, err
	}
	row, err := q.db.InsertDepExtractionRun(ctx, dbgen.InsertDepExtractionRunParams{
		RepoID:           params.RepoID,
		SnapshotID:       params.SnapshotID,
		CommitSha:        params.CommitSHA,
		InputDigest:      params.InputDigest,
		ExtractorVersion: params.ExtractorVersion,
		ArtifactID:       nullUUIDFromPtr(params.ArtifactID),
		ObjectKey:        params.ObjectKey,
		Sha256:           params.SHA256,
		SizeBytes:        params.SizeBytes,
		ComponentCount:   int32(params.ComponentCount), // #nosec G115 -- component counts are far below int32
		Modules:          encoded,
		Updaters:         encodedUpdaters,
		ReusedFrom:       nullUUIDFromPtr(params.ReusedFrom),
	})
	if err != nil {
		return nil, err
	}
	return depExtractionRunFromRow(row), nil
}

func (q *Queries) GetDepExtractionRunBySnapshot(ctx context.Context, snapshotID uuid.UUID) (*DepExtractionRun, error) {
	row, err := q.db.GetDepExtractionRunBySnapshot(ctx, snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionRunFromRow(row), nil
}

func (q *Queries) GetLatestDepExtractionRunByDigest(ctx context.Context, repoID uuid.UUID, inputDigest, extractorVersion string) (*DepExtractionRun, error) {
	row, err := q.db.GetLatestDepExtractionRunByDigest(ctx, dbgen.GetLatestDepExtractionRunByDigestParams{
		RepoID:           repoID,
		InputDigest:      inputDigest,
		ExtractorVersion: extractorVersion,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return depExtractionRunFromRow(row), nil
}

func depExtractionRunFromRow(row dbgen.DepExtractionRun) *DepExtractionRun {
	run := &DepExtractionRun{
		ID:               row.ID,
		RepoID:           row.RepoID,
		SnapshotID:       row.SnapshotID,
		CommitSHA:        row.CommitSha,
		InputDigest:      row.InputDigest,
		ExtractorVersion: row.ExtractorVersion,
		ObjectKey:        row.ObjectKey,
		SHA256:           row.Sha256,
		SizeBytes:        row.SizeBytes,
		ComponentCount:   int(row.ComponentCount),
		CreatedAt:        row.CreatedAt,
		Modules:          []DepExtractionModule{},
		Updaters:         []DepUpdaterConfig{},
	}
	if row.ArtifactID.Valid {
		id := row.ArtifactID.UUID
		run.ArtifactID = &id
	}
	if row.ReusedFrom.Valid {
		id := row.ReusedFrom.UUID
		run.ReusedFrom = &id
	}
	if len(row.Modules) > 0 {
		_ = json.Unmarshal(row.Modules, &run.Modules)
	}
	if len(row.Updaters) > 0 {
		_ = json.Unmarshal(row.Updaters, &run.Updaters)
	}
	return run
}

// OutdatedDepExtractionRun is a run made with another extractor version.
type OutdatedDepExtractionRun struct {
	ID               uuid.UUID
	RepoID           uuid.UUID
	SnapshotID       uuid.UUID
	ExtractorVersion string
	InputDigest      string
	CommitSHA        string
	RefName          string
}

// ListOutdatedDepExtractionRuns lists runs the upgrade pass should redo.
func (q *Queries) ListOutdatedDepExtractionRuns(ctx context.Context, currentVersion string, limit int) ([]OutdatedDepExtractionRun, error) {
	rows, err := q.db.ListOutdatedDepExtractionRuns(ctx, dbgen.ListOutdatedDepExtractionRunsParams{CurrentVersion: currentVersion, RowLimit: int32(limit)}) // #nosec G115 -- a small page size
	if err != nil {
		return nil, err
	}
	out := make([]OutdatedDepExtractionRun, 0, len(rows))
	for _, row := range rows {
		out = append(out, OutdatedDepExtractionRun{ID: row.ID, RepoID: row.RepoID, SnapshotID: row.SnapshotID, ExtractorVersion: row.ExtractorVersion, InputDigest: row.InputDigest, CommitSHA: row.CommitSha, RefName: row.RefName})
	}
	return out, nil
}
