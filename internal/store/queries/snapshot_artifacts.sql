-- name: CreateSnapshotArtifact :one
INSERT INTO snapshot_artifacts (
	snapshot_id,
	kind,
	format,
	tool_name,
	object_key,
	sha256,
	size_bytes,
	content_type
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListSnapshotArtifactsBySnapshot :many
SELECT * FROM snapshot_artifacts
WHERE snapshot_id = $1
ORDER BY created_at;

-- name: ListSnapshotArtifactObjectKeys :many
SELECT object_key FROM snapshot_artifacts
WHERE snapshot_id = $1
ORDER BY created_at;
