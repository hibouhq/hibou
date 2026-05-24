-- name: CreateSnapshot :one
INSERT INTO snapshots (ref_id, commit_sha, label, status, raw_artifact_url)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSnapshotByID :one
SELECT * FROM snapshots WHERE id = $1;

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

-- name: SetSnapshotArtifactKey :one
UPDATE snapshots SET artifact_key = $2 WHERE id = $1 RETURNING *;

-- name: ArchiveSnapshot :exec
UPDATE snapshots SET status = 'archived' WHERE id = $1;

-- name: PurgeSnapshot :exec
UPDATE snapshots SET status = 'purged' WHERE id = $1;

-- name: GetLatestSnapshotByRef :one
SELECT * FROM snapshots WHERE ref_id = $1 ORDER BY created_at DESC LIMIT 1;

-- name: ListComponentsBySnapshot :many
SELECT c.* FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
WHERE sc.snapshot_id = $1;

-- name: ListComponentsBySnapshotWithVulns :many
SELECT c.*, COUNT(DISTINCT vm.advisory_id)::bigint AS vuln_count
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
LEFT JOIN vuln_matches vm ON vm.snapshot_id = sc.snapshot_id AND vm.component_id = c.id AND vm.is_affected = TRUE
WHERE sc.snapshot_id = $1
GROUP BY c.id
ORDER BY c.name, c.version;

-- name: CountComponentsBySnapshot :one
SELECT COUNT(*)::bigint FROM snapshot_components WHERE snapshot_id = $1;
