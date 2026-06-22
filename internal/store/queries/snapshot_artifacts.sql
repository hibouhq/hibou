-- name: CreateSnapshotArtifact :one
INSERT INTO snapshot_artifacts (
	snapshot_id,
	kind,
	format,
	tool_name,
	object_key,
	sha256,
	size_bytes,
	content_type,
	filename
)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
WHERE NOT EXISTS (
	SELECT 1
	FROM snapshot_artifacts
	WHERE snapshot_id = $1 AND object_key = $5
)
RETURNING *;

-- name: ListSnapshotArtifactsBySnapshot :many
SELECT * FROM snapshot_artifacts
WHERE snapshot_id = $1
ORDER BY created_at;

-- name: GetSnapshotArtifactByID :one
SELECT * FROM snapshot_artifacts
WHERE id = $1;

-- name: ListSnapshotArtifactObjectKeys :many
SELECT object_key FROM snapshot_artifacts
WHERE snapshot_id = $1
ORDER BY created_at;

-- name: ListSnapshotArtifactObjectKeysByRepo :many
SELECT sa.object_key
FROM snapshot_artifacts sa
JOIN snapshots s ON s.id = sa.snapshot_id
JOIN refs rf ON rf.id = s.ref_id
WHERE rf.repo_id = $1 AND sa.object_key <> '';

-- name: ListSnapshotArtifactObjectKeysByOrg :many
SELECT sa.object_key
FROM snapshot_artifacts sa
JOIN snapshots s ON s.id = sa.snapshot_id
JOIN refs rf ON rf.id = s.ref_id
JOIN repositories r ON r.id = rf.repo_id
WHERE r.org_id = $1 AND sa.object_key <> '';
