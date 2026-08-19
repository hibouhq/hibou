-- name: UpsertWorkerHeartbeat :exec
-- Registers the replica on first beat and refreshes it afterwards. stopped_at
-- is cleared so an ID that beats again after a graceful stop reads as online.
INSERT INTO worker_instances (
	id, hostname, pid, version, loops, started_at, last_heartbeat_at,
	cpu_percent, memory_rss_bytes, heap_alloc_bytes, goroutines, gomaxprocs, active_jobs
)
VALUES (
	sqlc.arg(id), sqlc.arg(hostname), sqlc.arg(pid), sqlc.arg(version),
	sqlc.arg(loops), sqlc.arg(started_at), NOW(),
	sqlc.narg(cpu_percent), sqlc.narg(memory_rss_bytes), sqlc.narg(heap_alloc_bytes),
	sqlc.narg(goroutines), sqlc.narg(gomaxprocs), sqlc.arg(active_jobs)
)
ON CONFLICT (id) DO UPDATE SET
	last_heartbeat_at = NOW(),
	stopped_at = NULL,
	version = EXCLUDED.version,
	loops = EXCLUDED.loops,
	cpu_percent = EXCLUDED.cpu_percent,
	memory_rss_bytes = EXCLUDED.memory_rss_bytes,
	heap_alloc_bytes = EXCLUDED.heap_alloc_bytes,
	goroutines = EXCLUDED.goroutines,
	gomaxprocs = EXCLUDED.gomaxprocs,
	active_jobs = EXCLUDED.active_jobs;

-- name: MarkWorkerStopped :exec
UPDATE worker_instances SET stopped_at = NOW() WHERE id = sqlc.arg(id);

-- name: PruneWorkerInstances :execrows
-- Opportunistic cleanup during heartbeat: a replica silent for a week is gone.
DELETE FROM worker_instances WHERE last_heartbeat_at < NOW() - INTERVAL '7 days';

-- name: ListWorkerInstances :many
-- Fleet view: registry rows plus the number of leases each worker currently
-- holds, cross-checked against the claim columns rather than trusting the
-- self-reported active_jobs.
SELECT w.id,
	w.hostname,
	w.pid,
	w.version,
	w.loops,
	w.started_at,
	w.last_heartbeat_at,
	w.stopped_at,
	w.cpu_percent,
	w.memory_rss_bytes,
	w.heap_alloc_bytes,
	w.goroutines,
	w.gomaxprocs,
	w.active_jobs,
	(
		SELECT COUNT(*) FROM secret_scan_jobs j
		WHERE j.claimed_by = w.id AND j.status = 'processing' AND j.finished_at IS NULL
	)::bigint AS running_secret_scans,
	(
		SELECT COUNT(*) FROM snapshots s
		WHERE s.artifact_processing_claimed_by = w.id
			AND s.artifact_processing_finished_at IS NULL
	)::bigint AS running_artifact_jobs
FROM worker_instances w
WHERE w.last_heartbeat_at > NOW() - INTERVAL '24 hours'
ORDER BY w.started_at ASC, w.id ASC;
