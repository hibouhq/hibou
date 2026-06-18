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
SELECT * FROM snapshots
WHERE status = 'pending'
	AND created_at < $1
ORDER BY created_at ASC
LIMIT $2;

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
UPDATE snapshots
SET status = 'complete'
WHERE id = $1
	AND status = 'pending'
RETURNING *;

-- name: ArchiveSnapshot :exec
UPDATE snapshots SET status = 'archived' WHERE id = $1;

-- name: PurgeSnapshot :exec
UPDATE snapshots SET status = 'purged' WHERE id = $1;

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
LEFT JOIN vulnerabilities v ON v.snapshot_id = sc.snapshot_id AND v.component_id = c.id AND v.status NOT IN ('resolved', 'dismissed')
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
