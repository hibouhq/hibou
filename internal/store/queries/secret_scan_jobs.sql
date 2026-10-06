-- name: EnqueueSecretScanJob :one
-- A push burst on one branch must not become N clones: the partial unique index
-- collapses them into the pending row, widening its range to the newest commit
-- while keeping the earliest from_commit so nothing in between goes unscanned.
INSERT INTO secret_scan_jobs (repo_id, ref_name, mode, from_commit, to_commit, snapshot_id)
VALUES (
	sqlc.arg(repo_id),
	sqlc.arg(ref_name),
	sqlc.arg(mode),
	sqlc.arg(from_commit),
	sqlc.arg(to_commit),
	sqlc.narg(snapshot_id)
)
ON CONFLICT (repo_id, ref_name, mode) WHERE status = 'pending'
DO UPDATE SET
	to_commit = EXCLUDED.to_commit,
	snapshot_id = COALESCE(EXCLUDED.snapshot_id, secret_scan_jobs.snapshot_id)
RETURNING *;

-- name: ClaimNextSecretScanJob :one
-- Same shape as ClaimNextArtifactProcessingSnapshot: skip rows another worker
-- holds, reclaim leases that expired with the pod that owned them, and stop
-- retrying past max_attempts instead of looping forever.
WITH candidate AS (
	SELECT j.id
	FROM secret_scan_jobs j
	WHERE (
			j.status IN ('pending', 'processing')
			-- Failed-retry arm (mirrors ClaimNextArtifactProcessingSnapshot):
			-- FailSecretScanJob with mark_finished=false parks a retryable
			-- failure as status 'failed' with finished_at NULL. Without this
			-- arm those rows were never claimed again — zombies that the jobs
			-- view showed as running for weeks.
			--
			-- The backoff (5·attempts² minutes: 5m, then 20m) exists because a
			-- clone fails for host-level reasons — fork EAGAIN under pid or
			-- memory pressure, DNS blips — that outlast an immediate retry.
			-- Without it all attempts burn within seconds of each other inside
			-- the same crunch and a transient condition becomes a terminal
			-- failure. started_at is the previous claim's timestamp, so the
			-- window is measured from the attempt that failed.
			OR (
				j.status = 'failed' AND j.finished_at IS NULL
				AND (
					j.started_at IS NULL
					OR j.started_at < NOW() - make_interval(mins => 5 * j.attempts * j.attempts)
				)
			)
		)
		AND j.attempts < sqlc.arg(max_attempts)
		AND (
			j.claim_expires_at IS NULL
			OR j.claim_expires_at < NOW()
		)
	ORDER BY j.created_at ASC, j.id ASC
	FOR UPDATE SKIP LOCKED
	LIMIT 1
)
UPDATE secret_scan_jobs j
SET status = 'processing',
	claimed_by = sqlc.arg(worker_id),
	claim_expires_at = sqlc.arg(claim_expires_at),
	started_at = NOW(),
	attempts = j.attempts + 1,
	last_error = ''
FROM candidate
WHERE j.id = candidate.id
RETURNING j.*;

-- name: RenewSecretScanJobClaim :execrows
UPDATE secret_scan_jobs
SET claim_expires_at = sqlc.arg(claim_expires_at)
WHERE id = sqlc.arg(job_id)
	AND claimed_by = sqlc.arg(worker_id)
	AND finished_at IS NULL;

-- name: CompleteSecretScanJob :one
UPDATE secret_scan_jobs
SET status = 'complete',
	claimed_by = NULL,
	claim_expires_at = NULL,
	finished_at = NOW(),
	last_error = ''
WHERE id = sqlc.arg(job_id)
	AND claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: FailSecretScanJob :one
-- mark_finished false leaves the row claimable so the next worker retries it
-- until attempts hits the cap; true is terminal.
UPDATE secret_scan_jobs
SET status = 'failed',
	claimed_by = NULL,
	claim_expires_at = NULL,
	finished_at = CASE WHEN sqlc.arg(mark_finished)::bool THEN NOW() ELSE NULL END,
	last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(job_id)
	AND claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: ReleaseSecretScanJobClaims :execrows
-- Graceful shutdown: hand back everything this worker holds so a rolling
-- restart does not wait out the lease.
UPDATE secret_scan_jobs
SET status = 'pending',
	claimed_by = NULL,
	claim_expires_at = NULL
WHERE claimed_by = sqlc.arg(worker_id)
	AND finished_at IS NULL;

-- name: GetSecretScanJob :one
SELECT * FROM secret_scan_jobs WHERE id = $1;

-- name: CountPendingSecretScanJobs :one
-- Queue depth: the autoscaling signal for worker replicas. Unfinished 'failed'
-- rows are pending retries (see the claim's failed-retry arm), so they count.
SELECT COUNT(*) FROM secret_scan_jobs WHERE status IN ('pending', 'processing', 'failed') AND finished_at IS NULL;

-- name: ListSecretScanJobsByRepo :many
SELECT * FROM secret_scan_jobs
WHERE repo_id = $1
ORDER BY created_at DESC
LIMIT $2;
