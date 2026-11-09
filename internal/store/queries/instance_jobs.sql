-- ADR-025 instance jobs observability: the three persisted job sources
-- (secret_scan_jobs, snapshots.artifact_processing_*, scans) normalized into
-- one job-run shape. Status vocabulary: queued | running | complete | failed |
-- cancelled. "Running" always means an unexpired lease (or scans.running);
-- an expired lease reads as queued because any worker may reclaim it.

-- name: InstanceJobCounts :many
-- Current-state counters per kind, cheap enough for a 10s poll.
SELECT 'secret_scan'::text AS kind,
	COUNT(*) FILTER (
		WHERE j.status = 'pending'
			OR (j.status = 'processing' AND (j.claim_expires_at IS NULL OR j.claim_expires_at < NOW()))
	)::bigint AS queued,
	COUNT(*) FILTER (
		WHERE j.status = 'processing' AND j.claim_expires_at >= NOW()
	)::bigint AS running,
	COUNT(*) FILTER (
		WHERE j.status = 'complete' AND j.finished_at >= NOW() - INTERVAL '24 hours'
	)::bigint AS completed_24h,
	COUNT(*) FILTER (
		WHERE j.status = 'failed' AND j.finished_at >= NOW() - INTERVAL '24 hours'
	)::bigint AS failed_24h,
	COALESCE((SELECT MIN(x.created_at) FROM secret_scan_jobs x WHERE x.status = 'pending'), 'epoch'::timestamptz)::timestamptz AS oldest_queued_at
FROM secret_scan_jobs j
UNION ALL
SELECT 'dep_extraction'::text AS kind,
	COUNT(*) FILTER (
		WHERE j.status = 'pending'
			OR (j.status = 'processing' AND (j.claim_expires_at IS NULL OR j.claim_expires_at < NOW()))
	)::bigint AS queued,
	COUNT(*) FILTER (
		WHERE j.status = 'processing' AND j.claim_expires_at >= NOW()
	)::bigint AS running,
	COUNT(*) FILTER (
		WHERE j.status = 'complete' AND j.finished_at >= NOW() - INTERVAL '24 hours'
	)::bigint AS completed_24h,
	COUNT(*) FILTER (
		WHERE j.status = 'failed' AND j.finished_at >= NOW() - INTERVAL '24 hours'
	)::bigint AS failed_24h,
	COALESCE((SELECT MIN(x.created_at) FROM dep_extraction_jobs x WHERE x.status = 'pending'), 'epoch'::timestamptz)::timestamptz AS oldest_queued_at
FROM dep_extraction_jobs j
UNION ALL
SELECT 'artifact_processing'::text,
	COUNT(*) FILTER (
		WHERE s.artifact_processing_finished_at IS NULL
			AND (
				s.status = 'processing'
				OR s.status = 'complete'
				OR (s.status = 'failed' AND s.artifact_processing_attempts > 0)
			)
			AND s.artifact_processing_attempts < sqlc.arg(artifact_max_attempts)::int
			AND (s.artifact_processing_claim_expires_at IS NULL OR s.artifact_processing_claim_expires_at < NOW())
			AND EXISTS (
				SELECT 1 FROM snapshot_artifacts sa
				WHERE sa.snapshot_id = s.id
					AND (sa.kind = 'sarif' OR (sa.kind = 'sbom' AND sa.format IN ('cyclonedx-json', 'spdx-json')))
			)
	)::bigint,
	COUNT(*) FILTER (
		WHERE s.artifact_processing_finished_at IS NULL
			AND s.artifact_processing_claimed_by IS NOT NULL
			AND s.artifact_processing_claim_expires_at >= NOW()
	)::bigint,
	COUNT(*) FILTER (
		WHERE s.status = 'complete' AND s.artifact_processing_finished_at >= NOW() - INTERVAL '24 hours'
	)::bigint,
	COUNT(*) FILTER (
		WHERE s.status = 'failed' AND s.artifact_processing_finished_at >= NOW() - INTERVAL '24 hours'
	)::bigint,
	COALESCE((
		SELECT MIN(x.created_at) FROM snapshots x
		WHERE x.artifact_processing_finished_at IS NULL
			AND x.artifact_processing_started_at IS NULL
			AND x.status = 'processing'
	), 'epoch'::timestamptz)::timestamptz
FROM snapshots s
UNION ALL
SELECT 'advisory_scan'::text,
	COUNT(*) FILTER (WHERE sc.status = 'pending')::bigint,
	COUNT(*) FILTER (WHERE sc.status = 'running')::bigint,
	COUNT(*) FILTER (
		WHERE sc.status = 'complete' AND sc.completed_at >= NOW() - INTERVAL '24 hours'
	)::bigint,
	COUNT(*) FILTER (
		WHERE sc.status IN ('failed', 'cancelled') AND sc.completed_at >= NOW() - INTERVAL '24 hours'
	)::bigint,
	COALESCE((SELECT MIN(x.created_at) FROM scans x WHERE x.status = 'pending'), 'epoch'::timestamptz)::timestamptz
FROM scans sc
UNION ALL
SELECT 'forge_reconciliation'::text,
	(SELECT count(*) FROM forge_reconciliation WHERE next_due_at<=now() AND (claim_expires_at IS NULL OR claim_expires_at<now()))::bigint,
	(SELECT count(*) FROM forge_reconciliation WHERE claim_expires_at>=now())::bigint,
	COUNT(*) FILTER (WHERE finished_at>=now()-interval '24 hours' AND error='')::bigint,
	COUNT(*) FILTER (WHERE finished_at>=now()-interval '24 hours' AND error<>'')::bigint,
	COALESCE((SELECT min(next_due_at) FROM forge_reconciliation WHERE next_due_at<=now() AND (claim_expires_at IS NULL OR claim_expires_at<now())),'epoch'::timestamptz)::timestamptz
FROM forge_reconciliation_runs;

-- name: ListInstanceJobRuns :many
-- Timeline feed: every run that finished inside the window plus everything
-- still queued or running, newest first, row-capped by the caller.
SELECT * FROM (
	SELECT 'secret_scan'::text AS kind,
		j.id AS id,
		(o.slug || '/' || r.slug)::text AS label,
		(j.mode || ' · ' || j.ref_name)::text AS detail,
		CASE
			WHEN j.status = 'pending' THEN 'queued'
			WHEN j.status = 'processing' AND (j.claim_expires_at IS NULL OR j.claim_expires_at < NOW()) THEN 'queued'
			WHEN j.status = 'processing' THEN 'running'
			WHEN j.status = 'complete' THEN 'complete'
			ELSE 'failed'
		END::text AS status,
		j.created_at AS queued_at,
		j.started_at AS started_at,
		j.finished_at AS finished_at,
		COALESCE(j.claimed_by, '')::text AS worker_id,
		j.attempts AS attempts,
		j.last_error::text AS error
	FROM secret_scan_jobs j
	JOIN repositories r ON r.id = j.repo_id
	JOIN organizations o ON o.id = r.org_id
	WHERE j.finished_at IS NULL OR j.finished_at >= sqlc.arg(since)::timestamptz

	UNION ALL
	SELECT 'dep_extraction'::text AS kind,
		j.id AS id,
		(o.slug || '/' || r.slug)::text AS label,
		(j.reason || ' · ' || j.ref_name)::text AS detail,
		CASE
			WHEN j.status = 'pending' THEN 'queued'
			WHEN j.status = 'processing' AND (j.claim_expires_at IS NULL OR j.claim_expires_at < NOW()) THEN 'queued'
			WHEN j.status = 'processing' THEN 'running'
			WHEN j.status = 'complete' THEN 'complete'
			ELSE 'failed'
		END::text AS status,
		j.created_at AS queued_at,
		j.started_at AS started_at,
		j.finished_at AS finished_at,
		COALESCE(j.claimed_by, '')::text AS worker_id,
		j.attempts AS attempts,
		j.last_error::text AS error
	FROM dep_extraction_jobs j
	JOIN repositories r ON r.id = j.repo_id
	JOIN organizations o ON o.id = r.org_id
	WHERE j.finished_at IS NULL OR j.finished_at >= sqlc.arg(since)::timestamptz

	UNION ALL

	SELECT 'artifact_processing'::text,
		s.id,
		(o.slug || '/' || r.slug)::text,
		LEFT(s.commit_sha, 12)::text,
		CASE
			WHEN s.artifact_processing_finished_at IS NULL
				AND s.artifact_processing_claimed_by IS NOT NULL
				AND s.artifact_processing_claim_expires_at >= NOW() THEN 'running'
			WHEN s.artifact_processing_finished_at IS NOT NULL AND s.status = 'failed' THEN 'failed'
			WHEN s.artifact_processing_finished_at IS NOT NULL THEN 'complete'
			WHEN s.status = 'failed' AND s.artifact_processing_attempts >= sqlc.arg(artifact_max_attempts)::int THEN 'failed'
			ELSE 'queued'
		END::text,
		s.created_at,
		s.artifact_processing_started_at,
		s.artifact_processing_finished_at,
		COALESCE(s.artifact_processing_claimed_by, '')::text,
		s.artifact_processing_attempts,
		COALESCE(s.artifact_processing_last_error, '')::text
	FROM snapshots s
	JOIN repositories r ON r.id = s.repo_id
	JOIN organizations o ON o.id = s.org_id
	WHERE s.artifact_processing_finished_at >= sqlc.arg(since)::timestamptz
		OR (
			-- Unfinished: only rows the worker loop would actually touch, so
			-- ordinary snapshots without SARIF/SBOM artifacts stay out.
			s.artifact_processing_finished_at IS NULL
			AND (
				s.status = 'processing'
				OR s.status = 'complete'
				OR (s.status = 'failed' AND s.artifact_processing_attempts > 0)
			)
			AND EXISTS (
				SELECT 1 FROM snapshot_artifacts sa
				WHERE sa.snapshot_id = s.id
					AND (sa.kind = 'sarif' OR (sa.kind = 'sbom' AND sa.format IN ('cyclonedx-json', 'spdx-json')))
			)
		)

	UNION ALL

	SELECT 'advisory_scan'::text,
		sc.id,
		(o.slug || '/' || r.slug)::text,
		(sc.triggered_by || ' · ' || array_to_string(sc.providers_requested, ','))::text,
		CASE
			WHEN sc.status = 'pending' THEN 'queued'
			WHEN sc.status = 'running' THEN 'running'
			WHEN sc.status = 'complete' THEN 'complete'
			WHEN sc.status = 'cancelled' THEN 'cancelled'
			ELSE 'failed'
		END::text,
		sc.created_at,
		sc.started_at,
		sc.completed_at,
		''::text,
		0::int,
		sc.error_message::text
	FROM scans sc
	JOIN snapshots s ON s.id = sc.snapshot_id
	JOIN repositories r ON r.id = s.repo_id
	JOIN organizations o ON o.id = s.org_id
	WHERE sc.completed_at IS NULL OR sc.completed_at >= sqlc.arg(since)::timestamptz
	UNION ALL
	SELECT 'forge_reconciliation'::text, run.id,
		(job.provider || '/' || job.scope)::text, job.kind::text,
		CASE WHEN run.finished_at IS NULL THEN 'running'
			WHEN run.error='' THEN 'complete' ELSE 'failed' END::text,
		run.queued_at, run.started_at, run.finished_at,
		COALESCE(job.claimed_by::text,''), job.attempts, run.error::text
	FROM forge_reconciliation_runs run
	JOIN forge_reconciliation job ON job.id=run.job_id
	WHERE run.finished_at IS NULL OR run.finished_at>=sqlc.arg(since)::timestamptz
	UNION ALL
	SELECT 'forge_reconciliation'::text, job.claimed_by,
		(job.provider || '/' || job.scope)::text, job.kind::text, 'running'::text,
		job.next_due_at,job.last_attempt_at,NULL::timestamptz,job.claimed_by::text,job.attempts,''::text
	FROM forge_reconciliation job WHERE job.claim_expires_at>=now()
	AND NOT EXISTS(SELECT 1 FROM forge_reconciliation_runs run WHERE run.id=job.claimed_by)
) runs
ORDER BY COALESCE(runs.started_at, runs.queued_at) DESC, runs.id DESC
LIMIT sqlc.arg(max_rows);

-- name: InstanceJobStats :many
-- Time-bucketed throughput and latency percentiles over finished runs.
-- Buckets are aligned to bucket_seconds; duration = finished - started,
-- queue wait = started - queued.
WITH runs AS (
	SELECT 'secret_scan'::text AS kind,
		j.status AS status,
		j.created_at AS queued_at,
		j.started_at AS started_at,
		j.finished_at AS finished_at
	FROM secret_scan_jobs j
	WHERE j.finished_at >= sqlc.arg(since)::timestamptz
	UNION ALL
	SELECT 'dep_extraction'::text AS kind,
		j.status AS status,
		j.created_at AS queued_at,
		j.started_at AS started_at,
		j.finished_at AS finished_at
	FROM dep_extraction_jobs j
	WHERE j.finished_at >= sqlc.arg(since)::timestamptz
	UNION ALL
	SELECT 'artifact_processing'::text,
		CASE WHEN s.status = 'failed' THEN 'failed' ELSE 'complete' END,
		s.created_at,
		s.artifact_processing_started_at,
		s.artifact_processing_finished_at
	FROM snapshots s
	WHERE s.artifact_processing_finished_at >= sqlc.arg(since)::timestamptz
	UNION ALL
	SELECT 'advisory_scan'::text,
		CASE WHEN sc.status = 'complete' THEN 'complete' ELSE 'failed' END,
		sc.created_at,
		sc.started_at,
		sc.completed_at
	FROM scans sc
	WHERE sc.completed_at >= sqlc.arg(since)::timestamptz
	UNION ALL
	SELECT 'forge_reconciliation'::text,
		CASE WHEN error='' THEN 'complete' ELSE 'failed' END::text,
		queued_at, started_at, finished_at
	FROM forge_reconciliation_runs
	WHERE finished_at>=sqlc.arg(since)::timestamptz
)
SELECT runs.kind,
	to_timestamp(
		floor(extract(epoch FROM runs.finished_at) / sqlc.arg(bucket_seconds)::float8) * sqlc.arg(bucket_seconds)::float8
	)::timestamptz AS bucket,
	COUNT(*) FILTER (WHERE runs.status = 'complete')::bigint AS completed,
	COUNT(*) FILTER (WHERE runs.status <> 'complete')::bigint AS failed,
	COALESCE((percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM runs.finished_at - runs.started_at)::float8)
		FILTER (WHERE runs.started_at IS NOT NULL))::float8, 0)::float8 AS p50_duration_seconds,
	COALESCE((percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM runs.finished_at - runs.started_at)::float8)
		FILTER (WHERE runs.started_at IS NOT NULL))::float8, 0)::float8 AS p95_duration_seconds,
	COALESCE((percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM runs.started_at - runs.queued_at)::float8)
		FILTER (WHERE runs.started_at IS NOT NULL))::float8, 0)::float8 AS p50_wait_seconds,
	COALESCE((percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM runs.started_at - runs.queued_at)::float8)
		FILTER (WHERE runs.started_at IS NOT NULL))::float8, 0)::float8 AS p95_wait_seconds
FROM runs
GROUP BY runs.kind, bucket
ORDER BY runs.kind, bucket;

-- name: InstanceJobBaseline :many
-- The "standard base" for the anomaly rule: latency percentiles over the
-- 7 days preceding the stats window.
WITH runs AS (
	SELECT 'secret_scan'::text AS kind,
		j.created_at AS queued_at,
		j.started_at AS started_at,
		j.finished_at AS finished_at
	FROM secret_scan_jobs j
	WHERE j.finished_at >= sqlc.arg(since)::timestamptz - INTERVAL '7 days'
		AND j.finished_at < sqlc.arg(since)::timestamptz
		AND j.started_at IS NOT NULL
	UNION ALL
	SELECT 'dep_extraction'::text AS kind,
		j.created_at AS queued_at,
		j.started_at AS started_at,
		j.finished_at AS finished_at
	FROM dep_extraction_jobs j
	WHERE j.finished_at >= sqlc.arg(since)::timestamptz - INTERVAL '7 days'
		AND j.finished_at < sqlc.arg(since)::timestamptz
		AND j.started_at IS NOT NULL
	UNION ALL
	SELECT 'artifact_processing'::text,
		s.created_at,
		s.artifact_processing_started_at,
		s.artifact_processing_finished_at
	FROM snapshots s
	WHERE s.artifact_processing_finished_at >= sqlc.arg(since)::timestamptz - INTERVAL '7 days'
		AND s.artifact_processing_finished_at < sqlc.arg(since)::timestamptz
		AND s.artifact_processing_started_at IS NOT NULL
	UNION ALL
	SELECT 'advisory_scan'::text,
		sc.created_at,
		sc.started_at,
		sc.completed_at
	FROM scans sc
	WHERE sc.completed_at >= sqlc.arg(since)::timestamptz - INTERVAL '7 days'
		AND sc.completed_at < sqlc.arg(since)::timestamptz
		AND sc.started_at IS NOT NULL
	UNION ALL
	SELECT 'forge_reconciliation'::text, queued_at, started_at, finished_at
	FROM forge_reconciliation_runs
	WHERE finished_at>=sqlc.arg(since)::timestamptz-interval '7 days'
		AND finished_at<sqlc.arg(since)::timestamptz
)
SELECT runs.kind,
	COUNT(*)::bigint AS samples,
	(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM runs.finished_at - runs.started_at)::float8))::float8 AS p50_duration_seconds,
	(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM runs.finished_at - runs.started_at)::float8))::float8 AS p95_duration_seconds,
	(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM runs.started_at - runs.queued_at)::float8))::float8 AS p50_wait_seconds,
	(percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM runs.started_at - runs.queued_at)::float8))::float8 AS p95_wait_seconds
FROM runs
GROUP BY runs.kind
ORDER BY runs.kind;
