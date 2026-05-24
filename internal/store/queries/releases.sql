-- name: CreateRelease :one
INSERT INTO releases (repo_id, ref_id, snapshot_id, version, build_metadata, artifact_ids, provenance, published_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetReleaseByID :one
SELECT * FROM releases WHERE id = $1;

-- name: ListReleasesByRepo :many
SELECT * FROM releases WHERE repo_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: CountReleasesByRepo :one
SELECT COUNT(*)::bigint FROM releases WHERE repo_id = $1;

-- name: ListReleasesByOrg :many
SELECT r.* FROM releases r
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
ORDER BY r.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountReleasesByOrg :one
SELECT COUNT(*)::bigint FROM releases r
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1;

-- name: DeleteRelease :exec
DELETE FROM releases WHERE id = $1;
