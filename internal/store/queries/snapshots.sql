-- name: CreateSnapshot :one
INSERT INTO snapshots (ref_id, commit_sha, label, status, raw_artifact_url)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSnapshotByID :one
SELECT * FROM snapshots WHERE id = $1;

-- name: ListSnapshotsByRef :many
SELECT * FROM snapshots WHERE ref_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: CountSnapshotsByRef :one
SELECT COUNT(*)::bigint FROM snapshots WHERE ref_id = $1;

-- name: UpdateSnapshotStatus :one
UPDATE snapshots SET status = $2 WHERE id = $1 RETURNING *;

-- name: GetLatestSnapshotByRef :one
SELECT * FROM snapshots WHERE ref_id = $1 ORDER BY created_at DESC LIMIT 1;