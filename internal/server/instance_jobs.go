package server

import (
	"net/http"
	"time"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

// ADR-025: instance-admin observability over background jobs and workers.

const instanceJobTimelineMaxRows = int32(500)

// jobWindow is a validated ?window= value with the stats bucket that keeps
// chart resolution roughly constant across windows.
type jobWindow struct {
	Name          string
	Duration      time.Duration
	BucketSeconds int
}

var jobWindows = map[string]jobWindow{
	"1h":  {Name: "1h", Duration: time.Hour, BucketSeconds: 300},
	"6h":  {Name: "6h", Duration: 6 * time.Hour, BucketSeconds: 900},
	"24h": {Name: "24h", Duration: 24 * time.Hour, BucketSeconds: 3600},
	"7d":  {Name: "7d", Duration: 7 * 24 * time.Hour, BucketSeconds: 6 * 3600},
}

func parseJobWindow(r *http.Request) (jobWindow, bool) {
	raw := r.URL.Query().Get("window")
	if raw == "" {
		raw = "24h"
	}
	w, ok := jobWindows[raw]

	return w, ok
}

// requireInstanceAdmin applies the standard two-step instance-admin gate and
// reports whether the handler may proceed.
func (s *Server) requireInstanceAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if !s.isInstanceAdmin(r) {
		api.JSONError(w, http.StatusForbidden, "instance admin required")
		return false
	}

	return true
}

type instanceJobsWorker struct {
	*store.WorkerInstance
	// Status is derived from last_heartbeat_at: online within 3 heartbeat
	// intervals, stale beyond, stopped after a graceful shutdown.
	Status string `json:"status"`
}

type instanceJobsOverviewResponse struct {
	Kinds                    []store.InstanceJobKindCounts `json:"kinds"`
	Workers                  []instanceJobsWorker          `json:"workers"`
	HeartbeatIntervalSeconds float64                       `json:"heartbeat_interval_seconds"`
}

// @Summary      Instance jobs overview
// @Description  Per-kind queue counters and the worker fleet. Instance admins only.
// @Tags         instance
// @Produce      json
// @Success      200  {object}  api.Response{data=instanceJobsOverviewResponse}
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/jobs/overview [get]
func (s *Server) handleInstanceJobsOverview(w http.ResponseWriter, r *http.Request) {
	if !s.requireInstanceAdmin(w, r) {
		return
	}

	counts, err := s.queries.InstanceJobCounts(r.Context(), artifactProcessingMaxAttempts)
	if err != nil {
		s.log.Error().Err(err).Msg("instance job counts failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to load job counts")
		return
	}

	instances, err := s.queries.ListWorkerInstances(r.Context())
	if err != nil {
		s.log.Error().Err(err).Msg("listing worker instances failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to load workers")
		return
	}

	interval := s.artifactProcessingHeartbeatInterval()
	staleAfter := 3 * interval
	now := time.Now()
	workers := make([]instanceJobsWorker, 0, len(instances))
	for _, instance := range instances {
		status := "online"
		switch {
		case instance.StoppedAt != nil:
			status = "stopped"
		case now.Sub(instance.LastHeartbeatAt) > staleAfter:
			status = "stale"
		}
		workers = append(workers, instanceJobsWorker{WorkerInstance: instance, Status: status})
	}

	api.JSON(w, http.StatusOK, instanceJobsOverviewResponse{
		Kinds:                    counts,
		Workers:                  workers,
		HeartbeatIntervalSeconds: interval.Seconds(),
	})
}

type instanceJobsTimelineResponse struct {
	Window    string                 `json:"window"`
	Since     time.Time              `json:"since"`
	Runs      []store.InstanceJobRun `json:"runs"`
	MaxRows   int32                  `json:"max_rows"`
	Truncated bool                   `json:"truncated"`
}

// @Summary      Instance jobs timeline
// @Description  Job runs overlapping the window, newest first, row-capped. Instance admins only.
// @Tags         instance
// @Produce      json
// @Param        window  query  string  false  "Window: 1h, 6h, 24h (default) or 7d"
// @Success      200  {object}  api.Response{data=instanceJobsTimelineResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/jobs/timeline [get]
func (s *Server) handleInstanceJobsTimeline(w http.ResponseWriter, r *http.Request) {
	if !s.requireInstanceAdmin(w, r) {
		return
	}

	window, ok := parseJobWindow(r)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid window")
		return
	}

	since := time.Now().Add(-window.Duration)
	runs, err := s.queries.ListInstanceJobRuns(r.Context(), since, artifactProcessingMaxAttempts, instanceJobTimelineMaxRows)
	if err != nil {
		s.log.Error().Err(err).Msg("listing instance job runs failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to load job runs")
		return
	}

	api.JSON(w, http.StatusOK, instanceJobsTimelineResponse{
		Window:    window.Name,
		Since:     since,
		Runs:      runs,
		MaxRows:   instanceJobTimelineMaxRows,
		Truncated: int32(len(runs)) == instanceJobTimelineMaxRows, // #nosec G115 -- len capped by query LIMIT
	})
}

type instanceJobsStatsResponse struct {
	Window        string                         `json:"window"`
	Since         time.Time                      `json:"since"`
	BucketSeconds int                            `json:"bucket_seconds"`
	Buckets       []store.InstanceJobStatsBucket `json:"buckets"`
	Baselines     []store.InstanceJobBaseline    `json:"baselines"`
}

// @Summary      Instance jobs statistics
// @Description  Bucketed throughput and latency percentiles plus the trailing-7-day baseline. Instance admins only.
// @Tags         instance
// @Produce      json
// @Param        window  query  string  false  "Window: 1h, 6h, 24h (default) or 7d"
// @Success      200  {object}  api.Response{data=instanceJobsStatsResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/jobs/stats [get]
func (s *Server) handleInstanceJobsStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireInstanceAdmin(w, r) {
		return
	}

	window, ok := parseJobWindow(r)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid window")
		return
	}

	since := time.Now().Add(-window.Duration)
	buckets, err := s.queries.InstanceJobStats(r.Context(), since, window.BucketSeconds)
	if err != nil {
		s.log.Error().Err(err).Msg("instance job stats failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to load job stats")
		return
	}

	baselines, err := s.queries.InstanceJobBaseline(r.Context(), since)
	if err != nil {
		s.log.Error().Err(err).Msg("instance job baseline failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to load job baseline")
		return
	}

	api.JSON(w, http.StatusOK, instanceJobsStatsResponse{
		Window:        window.Name,
		Since:         since,
		BucketSeconds: window.BucketSeconds,
		Buckets:       buckets,
		Baselines:     baselines,
	})
}
