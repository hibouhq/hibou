package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Normalized job kinds and statuses served by the instance jobs endpoints
// (ADR-025). Mirrored by the CASE mappings in queries/instance_jobs.sql.
const (
	InstanceJobKindSecretScan         = "secret_scan"
	InstanceJobKindArtifactProcessing = "artifact_processing"
	InstanceJobKindAdvisoryScan       = "advisory_scan"

	InstanceJobStatusQueued    = "queued"
	InstanceJobStatusRunning   = "running"
	InstanceJobStatusComplete  = "complete"
	InstanceJobStatusFailed    = "failed"
	InstanceJobStatusCancelled = "cancelled"
)

type InstanceJobKindCounts struct {
	Kind         string     `json:"kind"`
	Queued       int64      `json:"queued"`
	Running      int64      `json:"running"`
	Completed24h int64      `json:"completed_24h"`
	Failed24h    int64      `json:"failed_24h"`
	OldestQueued *time.Time `json:"oldest_queued_at,omitempty"`
}

type InstanceJobRun struct {
	Kind       string     `json:"kind"`
	ID         uuid.UUID  `json:"id"`
	Label      string     `json:"label"`
	Detail     string     `json:"detail,omitempty"`
	Status     string     `json:"status"`
	QueuedAt   time.Time  `json:"queued_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	WorkerID   string     `json:"worker_id,omitempty"`
	Attempts   int32      `json:"attempts"`
	Error      string     `json:"error,omitempty"`
}

type InstanceJobStatsBucket struct {
	Kind               string    `json:"kind"`
	Bucket             time.Time `json:"bucket"`
	Completed          int64     `json:"completed"`
	Failed             int64     `json:"failed"`
	P50DurationSeconds float64   `json:"p50_duration_seconds"`
	P95DurationSeconds float64   `json:"p95_duration_seconds"`
	P50WaitSeconds     float64   `json:"p50_wait_seconds"`
	P95WaitSeconds     float64   `json:"p95_wait_seconds"`
}

type InstanceJobBaseline struct {
	Kind               string  `json:"kind"`
	Samples            int64   `json:"samples"`
	P50DurationSeconds float64 `json:"p50_duration_seconds"`
	P95DurationSeconds float64 `json:"p95_duration_seconds"`
	P50WaitSeconds     float64 `json:"p50_wait_seconds"`
	P95WaitSeconds     float64 `json:"p95_wait_seconds"`
}

func (q *Queries) InstanceJobCounts(ctx context.Context, artifactMaxAttempts int32) ([]InstanceJobKindCounts, error) {
	rows, err := q.db.InstanceJobCounts(ctx, artifactMaxAttempts)
	if err != nil {
		return nil, err
	}

	counts := make([]InstanceJobKindCounts, 0, len(rows))
	for _, row := range rows {
		c := InstanceJobKindCounts{
			Kind:         row.Kind,
			Queued:       row.Queued,
			Running:      row.Running,
			Completed24h: row.Completed24h,
			Failed24h:    row.Failed24h,
		}
		// The query coalesces "nothing queued" to the epoch sentinel.
		if row.OldestQueuedAt.Unix() > 0 {
			at := row.OldestQueuedAt
			c.OldestQueued = &at
		}
		counts = append(counts, c)
	}

	return counts, nil
}

func (q *Queries) ListInstanceJobRuns(ctx context.Context, since time.Time, artifactMaxAttempts, maxRows int32) ([]InstanceJobRun, error) {
	rows, err := q.db.ListInstanceJobRuns(ctx, dbgen.ListInstanceJobRunsParams{
		Since:               since,
		ArtifactMaxAttempts: artifactMaxAttempts,
		MaxRows:             maxRows,
	})
	if err != nil {
		return nil, err
	}

	runs := make([]InstanceJobRun, 0, len(rows))
	for _, row := range rows {
		run := InstanceJobRun{
			Kind:     row.Kind,
			ID:       row.ID,
			Label:    row.Label,
			Detail:   row.Detail,
			Status:   row.Status,
			QueuedAt: row.QueuedAt,
			WorkerID: row.WorkerID,
			Attempts: row.Attempts,
			Error:    row.Error,
		}
		if row.StartedAt.Valid {
			at := row.StartedAt.Time
			run.StartedAt = &at
		}
		if row.FinishedAt.Valid {
			at := row.FinishedAt.Time
			run.FinishedAt = &at
		}
		runs = append(runs, run)
	}

	return runs, nil
}

func (q *Queries) InstanceJobStats(ctx context.Context, since time.Time, bucketSeconds int) ([]InstanceJobStatsBucket, error) {
	rows, err := q.db.InstanceJobStats(ctx, dbgen.InstanceJobStatsParams{
		Since:         since,
		BucketSeconds: float64(bucketSeconds),
	})
	if err != nil {
		return nil, err
	}

	buckets := make([]InstanceJobStatsBucket, 0, len(rows))
	for _, row := range rows {
		buckets = append(buckets, InstanceJobStatsBucket{
			Kind:               row.Kind,
			Bucket:             row.Bucket,
			Completed:          row.Completed,
			Failed:             row.Failed,
			P50DurationSeconds: row.P50DurationSeconds,
			P95DurationSeconds: row.P95DurationSeconds,
			P50WaitSeconds:     row.P50WaitSeconds,
			P95WaitSeconds:     row.P95WaitSeconds,
		})
	}

	return buckets, nil
}

func (q *Queries) InstanceJobBaseline(ctx context.Context, since time.Time) ([]InstanceJobBaseline, error) {
	rows, err := q.db.InstanceJobBaseline(ctx, since)
	if err != nil {
		return nil, err
	}

	baselines := make([]InstanceJobBaseline, 0, len(rows))
	for _, row := range rows {
		baselines = append(baselines, InstanceJobBaseline{
			Kind:               row.Kind,
			Samples:            row.Samples,
			P50DurationSeconds: row.P50DurationSeconds,
			P95DurationSeconds: row.P95DurationSeconds,
			P50WaitSeconds:     row.P50WaitSeconds,
			P95WaitSeconds:     row.P95WaitSeconds,
		})
	}

	return baselines, nil
}
