package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// WorkerInstance is one registered replica (ADR-025). Resource numbers are
// self-reported and process-level, not cgroup limits. RunningJobs counts the
// leases the claim columns currently attribute to this worker, which may
// disagree with the self-reported ActiveJobs during a heartbeat gap.
type WorkerInstance struct {
	ID              string     `json:"id"`
	Hostname        string     `json:"hostname"`
	PID             int32      `json:"pid"`
	Version         string     `json:"version,omitempty"`
	Loops           []string   `json:"loops"`
	StartedAt       time.Time  `json:"started_at"`
	LastHeartbeatAt time.Time  `json:"last_heartbeat_at"`
	StoppedAt       *time.Time `json:"stopped_at,omitempty"`
	CPUPercent      *float64   `json:"cpu_percent,omitempty"`
	MemoryRSSBytes  *int64     `json:"memory_rss_bytes,omitempty"`
	HeapAllocBytes  *int64     `json:"heap_alloc_bytes,omitempty"`
	Goroutines      *int32     `json:"goroutines,omitempty"`
	GOMAXPROCS      *int32     `json:"gomaxprocs,omitempty"`
	ActiveJobs      int32      `json:"active_jobs"`
	RunningJobs     int64      `json:"running_jobs"`
}

type WorkerHeartbeat struct {
	ID             string
	Hostname       string
	PID            int32
	Version        string
	Loops          []string
	StartedAt      time.Time
	CPUPercent     *float64
	MemoryRSSBytes *int64
	HeapAllocBytes *int64
	Goroutines     *int32
	GOMAXPROCS     *int32
	ActiveJobs     int32
}

func (q *Queries) UpsertWorkerHeartbeat(ctx context.Context, hb WorkerHeartbeat) error {
	params := dbgen.UpsertWorkerHeartbeatParams{
		ID:         hb.ID,
		Hostname:   hb.Hostname,
		Pid:        hb.PID,
		Version:    hb.Version,
		Loops:      hb.Loops,
		StartedAt:  hb.StartedAt,
		ActiveJobs: hb.ActiveJobs,
	}
	if hb.CPUPercent != nil {
		params.CpuPercent = sql.NullFloat64{Float64: *hb.CPUPercent, Valid: true}
	}
	if hb.MemoryRSSBytes != nil {
		params.MemoryRssBytes = sql.NullInt64{Int64: *hb.MemoryRSSBytes, Valid: true}
	}
	if hb.HeapAllocBytes != nil {
		params.HeapAllocBytes = sql.NullInt64{Int64: *hb.HeapAllocBytes, Valid: true}
	}
	if hb.Goroutines != nil {
		params.Goroutines = sql.NullInt32{Int32: *hb.Goroutines, Valid: true}
	}
	if hb.GOMAXPROCS != nil {
		params.Gomaxprocs = sql.NullInt32{Int32: *hb.GOMAXPROCS, Valid: true}
	}

	return q.db.UpsertWorkerHeartbeat(ctx, params)
}

func (q *Queries) MarkWorkerStopped(ctx context.Context, id string) error {
	return q.db.MarkWorkerStopped(ctx, id)
}

func (q *Queries) PruneWorkerInstances(ctx context.Context) (int64, error) {
	return q.db.PruneWorkerInstances(ctx)
}

func (q *Queries) ListWorkerInstances(ctx context.Context) ([]*WorkerInstance, error) {
	rows, err := q.db.ListWorkerInstances(ctx)
	if err != nil {
		return nil, err
	}

	workers := make([]*WorkerInstance, 0, len(rows))
	for _, row := range rows {
		w := &WorkerInstance{
			ID:              row.ID,
			Hostname:        row.Hostname,
			PID:             row.Pid,
			Version:         row.Version,
			Loops:           row.Loops,
			StartedAt:       row.StartedAt,
			LastHeartbeatAt: row.LastHeartbeatAt,
			ActiveJobs:      row.ActiveJobs,
			RunningJobs:     row.RunningSecretScans + row.RunningArtifactJobs,
		}
		if w.Loops == nil {
			w.Loops = []string{}
		}
		if row.StoppedAt.Valid {
			at := row.StoppedAt.Time
			w.StoppedAt = &at
		}
		if row.CpuPercent.Valid {
			v := row.CpuPercent.Float64
			w.CPUPercent = &v
		}
		if row.MemoryRssBytes.Valid {
			v := row.MemoryRssBytes.Int64
			w.MemoryRSSBytes = &v
		}
		if row.HeapAllocBytes.Valid {
			v := row.HeapAllocBytes.Int64
			w.HeapAllocBytes = &v
		}
		if row.Goroutines.Valid {
			v := row.Goroutines.Int32
			w.Goroutines = &v
		}
		if row.Gomaxprocs.Valid {
			v := row.Gomaxprocs.Int32
			w.GOMAXPROCS = &v
		}
		workers = append(workers, w)
	}

	return workers, nil
}
