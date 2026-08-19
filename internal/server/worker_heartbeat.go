package server

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/version"
)

// runWorkerHeartbeatLoop keeps this replica's worker_instances row fresh
// (ADR-025). It runs on every replica regardless of role: API-only replicas
// also hold background loops worth seeing in the fleet view. Liveness is
// derived from last_heartbeat_at by readers, never stored.
func (s *Server) runWorkerHeartbeatLoop(ctx context.Context) {
	interval := s.artifactProcessingHeartbeatInterval()

	sampler := newResourceSampler()
	if _, err := s.queries.PruneWorkerInstances(ctx); err != nil {
		s.log.Warn().Err(err).Msg("pruning stale worker instances failed")
	}
	s.beatWorkerHeartbeat(ctx, sampler)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.beatWorkerHeartbeat(ctx, sampler)
		}
	}
}

func (s *Server) beatWorkerHeartbeat(ctx context.Context, sampler *resourceSampler) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}

	hb := store.WorkerHeartbeat{
		ID:         s.artifactWorkerID,
		Hostname:   hostname,
		PID:        int32(os.Getpid()), // #nosec G115 -- PIDs fit in int32 on supported platforms
		Version:    version.Version,
		Loops:      s.enabledLoops,
		StartedAt:  s.startedAt,
		ActiveJobs: s.activeJobCount(),
	}
	sampler.fill(&hb)

	if err := s.queries.UpsertWorkerHeartbeat(ctx, hb); err != nil {
		s.log.Warn().Err(err).Msg("worker heartbeat failed")
	}
}

// activeJobCount is the replica's self-reported in-flight work: artifact
// processing runs plus occupied secret-scan slots.
func (s *Server) activeJobCount() int32 {
	s.artifactStateMu.Lock()
	count := s.activeArtifacts
	s.artifactStateMu.Unlock()
	if s.secretScanSlots != nil {
		count += len(s.secretScanSlots)
	}

	return int32(count) // #nosec G115 -- bounded by per-replica concurrency slots
}

// resourceSampler produces the self-reported, process-level resource numbers
// on each heartbeat. CPU is the share of one core used since the previous
// sample; memory is RSS plus the Go heap. These are not cgroup limits and the
// UI labels them accordingly.
type resourceSampler struct {
	lastCPUSeconds float64
	lastSampledAt  time.Time
}

func newResourceSampler() *resourceSampler {
	sampler := &resourceSampler{}
	if cpu, ok := processCPUSeconds(); ok {
		sampler.lastCPUSeconds = cpu
		sampler.lastSampledAt = time.Now()
	}

	return sampler
}

func (rs *resourceSampler) fill(hb *store.WorkerHeartbeat) {
	if cpu, ok := processCPUSeconds(); ok {
		now := time.Now()
		if !rs.lastSampledAt.IsZero() {
			elapsed := now.Sub(rs.lastSampledAt).Seconds()
			if elapsed > 0 {
				pct := (cpu - rs.lastCPUSeconds) / elapsed * 100
				if pct < 0 {
					pct = 0
				}
				hb.CPUPercent = &pct
			}
		}
		rs.lastCPUSeconds = cpu
		rs.lastSampledAt = now
	}

	if rss, ok := processRSSBytes(); ok {
		hb.MemoryRSSBytes = &rss
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	heap := int64(mem.HeapAlloc) // #nosec G115 -- heap size fits in int64
	hb.HeapAllocBytes = &heap

	goroutines := int32(runtime.NumGoroutine()) // #nosec G115 -- goroutine counts fit in int32
	hb.Goroutines = &goroutines
	maxprocs := int32(runtime.GOMAXPROCS(0)) // #nosec G115 -- CPU counts fit in int32
	hb.GOMAXPROCS = &maxprocs
}
