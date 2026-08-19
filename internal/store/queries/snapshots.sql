-- name: CreateSnapshot :one
INSERT INTO snapshots (ref_id, commit_sha, status)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSnapshotByID :one
SELECT * FROM snapshots WHERE id = $1;

-- name: GetSnapshotByRefCommit :one
SELECT * FROM snapshots WHERE ref_id = $1 AND commit_sha = $2;

-- name: GetSnapshotByBuildIdentity :one
SELECT *
FROM snapshots
WHERE ref_id = $1
	AND commit_sha = $2
	AND COALESCE(run_id, '') = COALESCE($3, '')
	AND COALESCE(run_attempt, '') = COALESCE($4, '')
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetLatestSnapshotForBuild :one
SELECT * FROM snapshots
WHERE ref_id = $1
	AND commit_sha = $2
	AND COALESCE(run_id, '') = COALESCE($3, '')
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: CountSnapshotsForBuild :one
SELECT COUNT(*)::bigint FROM snapshots
WHERE ref_id = $1
	AND commit_sha = $2
	AND COALESCE(run_id, '') = COALESCE($3, '');

-- name: GetSnapshotAtDate :one
SELECT s.* FROM snapshots s
JOIN refs r ON r.id = s.ref_id
WHERE r.repo_id = $1
	AND r.name = $2
	AND s.created_at <= $3
	AND s.status != 'purged'
ORDER BY s.created_at DESC
LIMIT 1;

-- name: ListSnapshotsByRef :many
SELECT * FROM snapshots WHERE ref_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: ListExpiredSnapshots :many
SELECT * FROM snapshots
WHERE created_at < $1
	AND status IN ('complete', 'active')
ORDER BY created_at ASC
LIMIT $2;

-- name: ListStalePendingSnapshots :many
-- Two leashes: a snapshot a build has touched (run metadata or received
-- uploads) that then stalls is stale after the upload window, but a run-less
-- zero-upload placeholder (created by a push/PR webhook before CI reaches its
-- upload step) gets the longer placeholder window — failing it at the upload
-- window would paint a red chip in the middle of every build slower than the
-- window, and the eventual upload could no longer adopt the row.
SELECT * FROM snapshots
WHERE status = 'pending'
	AND CASE WHEN run_id IS NULL AND received_uploads = 0
		THEN created_at < sqlc.arg(placeholder_before)
		ELSE created_at < sqlc.arg(started_before)
	END
ORDER BY created_at ASC
LIMIT sqlc.arg(row_limit);

-- name: ListArchivedSnapshotsForPurge :many
SELECT * FROM snapshots
WHERE created_at < $1
	AND status = 'archived'
ORDER BY created_at ASC
LIMIT $2;

-- name: CountSnapshotsByRef :one
SELECT COUNT(*)::bigint FROM snapshots WHERE ref_id = $1;

-- name: UpdateSnapshotStatus :one
UPDATE snapshots SET status = $2 WHERE id = $1 RETURNING *;

-- name: MarkSnapshotFailedIfPending :execrows
UPDATE snapshots SET status = 'failed' WHERE id = $1 AND status = 'pending';

-- name: IncrementSnapshotReceivedUploads :one
UPDATE snapshots
SET received_uploads = received_uploads + 1
WHERE id = $1
RETURNING *;

-- name: CompleteSnapshot :one
-- Finalizing an upload does not mean the data is ready: SBOM/SARIF artifacts
-- are ingested by the async worker afterwards. Land on 'processing' while any
-- such artifact is queued (the predicate mirrors the worker's claim query) so
-- data views and gates keep reading the previous complete snapshot; the worker
-- flips to 'complete' when ingestion finishes. Coverage/tests ingest at upload
-- time, so artifact-less snapshots complete immediately.
UPDATE snapshots
SET status = CASE
	WHEN EXISTS (
		SELECT 1
		FROM snapshot_artifacts sa
		WHERE sa.snapshot_id = snapshots.id
			AND (
				sa.kind = 'sarif'
				OR (sa.kind = 'sbom' AND sa.format IN ('cyclonedx-json', 'spdx-json'))
			)
	) THEN 'processing'::snapshot_status
	ELSE 'complete'::snapshot_status
END
WHERE snapshots.id = $1
	AND snapshots.status = 'pending'
RETURNING *;

-- name: ClaimNextArtifactProcessingSnapshot :one
WITH candidate AS (
	SELECT s.id
	FROM snapshots s
	WHERE (
			s.status = 'processing'
			-- 'complete' arm: rows finalized before status 'processing' existed.
			OR s.status = 'complete'
			OR (s.status = 'failed' AND s.artifact_processing_attempts > 0)
		)
		AND s.artifact_processing_finished_at IS NULL
		AND s.artifact_processing_attempts < sqlc.arg(max_attempts)
		AND (
			s.artifact_processing_claim_expires_at IS NULL
			OR s.artifact_processing_claim_expires_at < NOW()
		)
		AND EXISTS (
			SELECT 1
			FROM snapshot_artifacts sa
			WHERE sa.snapshot_id = s.id
				AND (
					sa.kind = 'sarif'
					OR (sa.kind = 'sbom' AND sa.format IN ('cyclonedx-json', 'spdx-json'))
				)
		)
	ORDER BY s.created_at ASC, s.id ASC
	FOR UPDATE SKIP LOCKED
	LIMIT 1
)
UPDATE snapshots s
SET artifact_processing_claimed_by = sqlc.arg(worker_id),
	artifact_processing_claim_expires_at = sqlc.arg(claim_expires_at),
	artifact_processing_started_at = NOW(),
	artifact_processing_attempts = s.artifact_processing_attempts + 1,
	artifact_processing_last_error = NULL
FROM candidate
WHERE s.id = candidate.id
RETURNING s.*;

-- name: CompleteArtifactProcessingSnapshot :one
UPDATE snapshots
SET status = 'complete',
	artifact_processing_claimed_by = NULL,
	artifact_processing_claim_expires_at = NULL,
	artifact_processing_finished_at = NOW(),
	artifact_processing_last_error = NULL
WHERE id = sqlc.arg(snapshot_id)
	AND artifact_processing_claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: CompleteArtifactProcessingSnapshotWithWarning :one
UPDATE snapshots
SET status = 'complete',
	artifact_processing_claimed_by = NULL,
	artifact_processing_claim_expires_at = NULL,
	artifact_processing_finished_at = NOW(),
	artifact_processing_last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(snapshot_id)
	AND artifact_processing_claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: RenewArtifactProcessingSnapshotClaim :execrows
UPDATE snapshots
SET artifact_processing_claim_expires_at = sqlc.arg(claim_expires_at)
WHERE id = sqlc.arg(snapshot_id)
	AND artifact_processing_claimed_by = sqlc.arg(worker_id)
	AND artifact_processing_finished_at IS NULL;

-- name: FailArtifactProcessingSnapshot :one
UPDATE snapshots
SET status = 'failed',
	artifact_processing_claimed_by = NULL,
	artifact_processing_claim_expires_at = NULL,
	artifact_processing_finished_at = CASE WHEN sqlc.arg(mark_finished)::bool THEN NOW() ELSE NULL END,
	artifact_processing_last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(snapshot_id)
	AND artifact_processing_claimed_by = sqlc.arg(worker_id)
RETURNING *;

-- name: ReleaseArtifactProcessingClaims :execrows
UPDATE snapshots
SET artifact_processing_claimed_by = NULL,
	artifact_processing_claim_expires_at = NULL
WHERE artifact_processing_claimed_by = sqlc.arg(worker_id)
	AND artifact_processing_finished_at IS NULL
	AND (status = 'processing' OR status = 'complete' OR status = 'failed');

-- name: ArchiveSnapshot :exec
WITH target AS (
	SELECT s.id, s.ref_id, s.artifact_bytes
	FROM snapshots s
	WHERE s.id = $1
	FOR UPDATE
), snapshot_update AS (
	UPDATE snapshots s
	SET status = 'archived',
		artifact_bytes = 0
	FROM target t
	WHERE s.id = t.id
	RETURNING t.ref_id, t.artifact_bytes AS reclaimed_bytes
)
UPDATE repositories repo
SET retention_artifact_bytes = GREATEST(0, repo.retention_artifact_bytes - su.reclaimed_bytes)
FROM refs r
JOIN snapshot_update su ON su.ref_id = r.id
WHERE repo.id = r.repo_id;

-- name: PurgeSnapshot :exec
WITH target AS (
	SELECT s.id, s.ref_id, s.artifact_bytes
	FROM snapshots s
	WHERE s.id = $1
	FOR UPDATE
), snapshot_update AS (
	UPDATE snapshots s
	SET status = 'purged',
		artifact_bytes = 0
	FROM target t
	WHERE s.id = t.id
	RETURNING t.ref_id, t.artifact_bytes AS reclaimed_bytes
)
UPDATE repositories repo
SET retention_artifact_bytes = GREATEST(0, repo.retention_artifact_bytes - su.reclaimed_bytes)
FROM refs r
JOIN snapshot_update su ON su.ref_id = r.id
WHERE repo.id = r.repo_id;

-- name: ListSnapshotsForRetentionTimeline :many
SELECT s.*
FROM snapshots s
JOIN refs r ON r.id = s.ref_id
WHERE r.repo_id = $1
	AND s.ref_id = $2
	AND s.status != 'purged'
ORDER BY s.created_at ASC, s.id ASC;

-- name: AddSnapshotArtifactBytes :exec
WITH snapshot_update AS (
	UPDATE snapshots s
	SET artifact_bytes = artifact_bytes + $2
	WHERE s.id = $1
	RETURNING s.ref_id
)
UPDATE repositories repo
SET retention_artifact_bytes = retention_artifact_bytes + $2
FROM refs r
JOIN snapshot_update su ON su.ref_id = r.id
WHERE repo.id = r.repo_id;

-- name: LockSnapshotForUpdate :one
SELECT id FROM snapshots
WHERE id = $1
FOR UPDATE;

-- name: UpdateSnapshotRetentionFlags :one
UPDATE snapshots
SET pinned = $2,
	retention_hold = $3
WHERE id = $1
RETURNING *;

-- name: GetLatestSnapshotByRef :one
SELECT * FROM snapshots WHERE ref_id = $1 ORDER BY created_at DESC LIMIT 1;

-- name: GetLatestCompleteSnapshotByRef :one
SELECT * FROM snapshots WHERE ref_id = $1 AND status IN ('complete', 'active') ORDER BY created_at DESC LIMIT 1;

-- name: ListComponentsBySnapshot :many
SELECT c.* FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
WHERE sc.snapshot_id = $1;

-- name: ListComponentsBySnapshotWithVulns :many
SELECT c.*, COUNT(DISTINCT v.id)::bigint AS vuln_count
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
LEFT JOIN vulnerabilities v ON v.snapshot_id = sc.snapshot_id AND v.component_id = c.id AND v.status NOT IN ('resolved', 'suppressed')
  AND NOT EXISTS (
    SELECT 1 FROM finding_acceptances fa
    WHERE fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
      AND fa.reason_kind = 'false_positive'
      AND (fa.expires_at IS NULL OR fa.expires_at > now())
  )
WHERE sc.snapshot_id = $1
GROUP BY c.id
ORDER BY c.name, c.version;

-- name: CountComponentsBySnapshot :one
SELECT COUNT(*)::bigint FROM snapshot_components WHERE snapshot_id = $1;

-- name: CreateSnapshotWithLabels :one
INSERT INTO snapshots (ref_id, commit_sha, status, labels, image_digest)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpsertSnapshotForBuild :one
INSERT INTO snapshots (
	ref_id,
	commit_sha,
	status,
	build_url,
	run_id,
	run_attempt,
	run_number,
	pr_number,
	pr_target_branch,
	tag,
	expected_uploads
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (ref_id, commit_sha, COALESCE(run_id, ''), COALESCE(run_attempt, '')) DO UPDATE SET
	build_url = COALESCE(snapshots.build_url, EXCLUDED.build_url),
	run_id = COALESCE(snapshots.run_id, EXCLUDED.run_id),
	run_attempt = COALESCE(snapshots.run_attempt, EXCLUDED.run_attempt),
	run_number = COALESCE(snapshots.run_number, EXCLUDED.run_number),
	pr_number = COALESCE(snapshots.pr_number, EXCLUDED.pr_number),
	pr_target_branch = COALESCE(snapshots.pr_target_branch, EXCLUDED.pr_target_branch),
	tag = COALESCE(snapshots.tag, EXCLUDED.tag),
	expected_uploads = COALESCE(snapshots.expected_uploads, EXCLUDED.expected_uploads)
RETURNING *;

-- name: ListSnapshotsByRefWithLabels :many
SELECT * FROM snapshots WHERE ref_id = $1 AND labels @> $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4;

-- name: GetLatestSnapshotByRepoAndSHA :one
-- Reachability results arrive after the upload; the commit names the snapshot.
SELECT * FROM snapshots
WHERE repo_id = $1 AND commit_sha = $2
ORDER BY created_at DESC
LIMIT 1;

-- name: UpsertSnapshotCodeRefs :exec
-- Each language's inventory only overwrites itself: analyses for different
-- languages arrive as separate posts and must not clobber each other.
INSERT INTO snapshot_code_refs (snapshot_id, go_symbols, java_packages, rust_referenced, rust_present, updated_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (snapshot_id) DO UPDATE SET
    go_symbols = CASE WHEN cardinality(EXCLUDED.go_symbols) > 0 THEN EXCLUDED.go_symbols ELSE snapshot_code_refs.go_symbols END,
    java_packages = CASE WHEN cardinality(EXCLUDED.java_packages) > 0 THEN EXCLUDED.java_packages ELSE snapshot_code_refs.java_packages END,
    rust_referenced = CASE WHEN cardinality(EXCLUDED.rust_referenced) > 0 OR cardinality(EXCLUDED.rust_present) > 0 THEN EXCLUDED.rust_referenced ELSE snapshot_code_refs.rust_referenced END,
    rust_present = CASE WHEN cardinality(EXCLUDED.rust_referenced) > 0 OR cardinality(EXCLUDED.rust_present) > 0 THEN EXCLUDED.rust_present ELSE snapshot_code_refs.rust_present END,
    updated_at = NOW();

-- name: GetSnapshotCodeRefs :one
SELECT * FROM snapshot_code_refs WHERE snapshot_id = $1;

-- name: RepoHasUploadActivity :one
-- Whether any snapshot of this repo ever received a CI upload. Distinguishes
-- upload-connected repos (a scan placeholder waits for CI to adopt it) from
-- scan-only repos (the placeholder must self-complete or findings stay dark).
SELECT EXISTS (
	SELECT 1
	FROM snapshots s
	JOIN refs r ON r.id = s.ref_id
	WHERE r.repo_id = $1 AND s.received_uploads > 0
)::bool AS has_uploads;

-- name: CreatePlaceholderSnapshot :one
-- Webhook-created pending snapshot for a PR head that has no snapshot yet, so
-- the UI shows the head as awaited and the CI upload adopts the row instead of
-- racing it. No-op (no row) when any snapshot already exists for the commit.
INSERT INTO snapshots (ref_id, commit_sha, status)
SELECT $1, $2, 'pending'
WHERE NOT EXISTS (
	SELECT 1 FROM snapshots WHERE ref_id = $1 AND commit_sha = $2
)
RETURNING *;

-- name: AdoptPlaceholderSnapshot :one
-- A CI upload claims the webhook's placeholder row for its build. The
-- placeholder is created by the PR webhook, which fires on push BEFORE any CI
-- run exists (the webhook payload has no run info), so it is keyed with
-- run_id IS NULL — an upload carrying a run_id would miss the upsert's
-- conflict key and insert a duplicate. A second run for the same commit finds
-- no placeholder left and takes the normal upsert path.
--
-- A failed row with zero uploads is a placeholder the stale sweep gave up on
-- before the build reached its upload step: the arriving upload proves the
-- build alive, so it is resurrected to pending rather than duplicated. A
-- genuinely failed upload (received_uploads > 0 or run metadata) stays failed.
UPDATE snapshots SET
	status = 'pending',
	build_url = COALESCE($3, build_url),
	run_id = $4,
	run_attempt = $5,
	run_number = $6,
	pr_number = COALESCE($7, pr_number),
	pr_target_branch = COALESCE($8, pr_target_branch),
	tag = COALESCE($9, tag),
	expected_uploads = COALESCE($10, expected_uploads)
WHERE ref_id = $1 AND commit_sha = $2 AND run_id IS NULL
	AND (status = 'pending' OR (status = 'failed' AND received_uploads = 0))
RETURNING *;
