-- name: EnqueueDepExtractionJob :one
-- A pending job for the same (repo, ref) absorbs the newer commit instead of
-- queueing another clone.
INSERT INTO dep_extraction_jobs (repo_id, ref_name, commit_sha, reason, snapshot_id)
VALUES (
	sqlc.arg(repo_id),
	sqlc.arg(ref_name),
	sqlc.arg(commit_sha),
	sqlc.arg(reason),
	sqlc.narg(snapshot_id)
)
ON CONFLICT (repo_id, ref_name) WHERE status = 'pending'
DO UPDATE SET
	commit_sha = CASE WHEN EXCLUDED.commit_sha <> '' THEN EXCLUDED.commit_sha ELSE dep_extraction_jobs.commit_sha END,
	reason = EXCLUDED.reason,
	snapshot_id = COALESCE(EXCLUDED.snapshot_id, dep_extraction_jobs.snapshot_id)
RETURNING *;

-- name: ClaimNextDepExtractionJob :one
-- Same fairness as secret scans: the org served longest ago goes first.
WITH org_last_served AS (
	SELECT r.org_id, MAX(served.started_at) AS last_started_at
	FROM dep_extraction_jobs served
	JOIN repositories r ON r.id = served.repo_id
	WHERE served.started_at > NOW() - INTERVAL '1 day'
	GROUP BY r.org_id
),
candidate AS (
	SELECT j.id
	FROM dep_extraction_jobs j
	JOIN repositories repo ON repo.id = j.repo_id
	LEFT JOIN org_last_served ols ON ols.org_id = repo.org_id
	WHERE (
			j.status IN ('pending', 'processing')
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
	ORDER BY ols.last_started_at ASC NULLS FIRST, j.created_at ASC, j.id ASC
	FOR UPDATE OF j SKIP LOCKED
	LIMIT 1
)
UPDATE dep_extraction_jobs j
SET status = 'processing',
	claimed_by = sqlc.arg(worker_id),
	claim_expires_at = sqlc.arg(claim_expires_at),
	started_at = NOW(),
	attempts = j.attempts + 1,
	last_error = ''
FROM candidate
WHERE j.id = candidate.id
RETURNING j.*;

-- name: RenewDepExtractionJobClaim :execrows
UPDATE dep_extraction_jobs
SET claim_expires_at = sqlc.arg(claim_expires_at)
WHERE id = sqlc.arg(job_id)
	AND claimed_by = sqlc.arg(worker_id)
	AND finished_at IS NULL;

-- name: CompleteDepExtractionJob :one
UPDATE dep_extraction_jobs
SET status = 'complete',
	claimed_by = NULL,
	claim_expires_at = NULL,
	finished_at = NOW(),
	last_error = '',
	snapshot_id = COALESCE(sqlc.narg(snapshot_id), snapshot_id)
WHERE id = sqlc.arg(job_id)
	AND claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: FailDepExtractionJob :one
UPDATE dep_extraction_jobs
SET status = 'failed',
	claimed_by = NULL,
	claim_expires_at = NULL,
	finished_at = CASE WHEN sqlc.arg(mark_finished)::bool THEN NOW() ELSE NULL END,
	last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(job_id)
	AND claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: ReleaseDepExtractionJobClaims :execrows
UPDATE dep_extraction_jobs
SET status = 'pending',
	claimed_by = NULL,
	claim_expires_at = NULL
WHERE claimed_by = sqlc.arg(worker_id)
	AND finished_at IS NULL;

-- name: GetDepExtractionJob :one
SELECT * FROM dep_extraction_jobs WHERE id = $1;

-- name: ListDepExtractionJobsByRepo :many
SELECT * FROM dep_extraction_jobs
WHERE repo_id = sqlc.arg(repo_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit);

-- name: CountPendingDepExtractionJobs :one
SELECT count(*)::bigint FROM dep_extraction_jobs WHERE status = 'pending';

-- name: InsertDepExtractionRun :one
INSERT INTO dep_extraction_runs (
	repo_id, snapshot_id, commit_sha, input_digest, extractor_version,
	artifact_id, object_key, sha256, size_bytes, component_count, modules, updaters, reused_from
)
VALUES (
	sqlc.arg(repo_id), sqlc.arg(snapshot_id), sqlc.arg(commit_sha), sqlc.arg(input_digest), sqlc.arg(extractor_version),
	sqlc.narg(artifact_id), sqlc.arg(object_key), sqlc.arg(sha256), sqlc.arg(size_bytes), sqlc.arg(component_count), sqlc.arg(modules), sqlc.arg(updaters), sqlc.narg(reused_from)
)
ON CONFLICT (snapshot_id) DO UPDATE SET
	input_digest = EXCLUDED.input_digest,
	extractor_version = EXCLUDED.extractor_version,
	artifact_id = EXCLUDED.artifact_id,
	object_key = EXCLUDED.object_key,
	sha256 = EXCLUDED.sha256,
	size_bytes = EXCLUDED.size_bytes,
	component_count = EXCLUDED.component_count,
	modules = EXCLUDED.modules,
	updaters = EXCLUDED.updaters,
	reused_from = EXCLUDED.reused_from,
	created_at = now()
RETURNING *;

-- name: GetDepExtractionRunBySnapshot :one
SELECT * FROM dep_extraction_runs WHERE snapshot_id = $1;

-- name: GetLatestDepExtractionRunByDigest :one
-- The most recent run of this repository with the same inputs and the same
-- extractor: its document is the answer.
SELECT * FROM dep_extraction_runs
WHERE repo_id = sqlc.arg(repo_id)
	AND input_digest = sqlc.arg(input_digest)
	AND extractor_version = sqlc.arg(extractor_version)
	AND reused_from IS NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: GetLatestDepExtractionJobForRef :one
SELECT * FROM dep_extraction_jobs
WHERE repo_id = sqlc.arg(repo_id) AND ref_name = sqlc.arg(ref_name)
ORDER BY created_at DESC
LIMIT 1;

-- name: ListOutdatedDepExtractionRuns :many
-- Runs made with another extractor version, on the default branch's
-- snapshots or on snapshots a release pins (ADR-045 §4.3.1), with no job
-- already queued for them. Newest first.
SELECT r.id, r.repo_id, r.snapshot_id, r.extractor_version, r.input_digest, s.commit_sha, rf.name AS ref_name
FROM dep_extraction_runs r
JOIN snapshots s ON s.id = r.snapshot_id
JOIN refs rf ON rf.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE r.extractor_version <> sqlc.arg(current_version)
  AND (rf.name = repo.default_branch
       OR EXISTS (SELECT 1 FROM releases rel WHERE rel.snapshot_id = r.snapshot_id))
  AND NOT EXISTS (SELECT 1 FROM dep_extraction_jobs j WHERE j.snapshot_id = r.snapshot_id AND j.status IN ('pending', 'processing'))
ORDER BY r.created_at DESC
LIMIT sqlc.arg(row_limit);
