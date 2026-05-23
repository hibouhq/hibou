-- name: CreateRef :one
INSERT INTO refs (repo_id, name, ref_type, provider_id, merge_target_ref_id, latest_commit_sha)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetRefByID :one
SELECT * FROM refs WHERE id = $1;

-- name: GetRefByRepoAndName :one
SELECT * FROM refs WHERE repo_id = $1 AND name = $2 AND ref_type = $3;

-- name: ListRefsByRepo :many
SELECT * FROM refs WHERE repo_id = $1 ORDER BY name ASC LIMIT $2 OFFSET $3;

-- name: CountRefsByRepo :one
SELECT COUNT(*)::bigint FROM refs WHERE repo_id = $1;

-- name: UpdateRefLatestCommit :one
UPDATE refs SET latest_commit_sha = $2, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: UpsertRef :one
INSERT INTO refs (repo_id, name, ref_type, provider_id, latest_commit_sha)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (repo_id, name, ref_type) DO UPDATE SET latest_commit_sha = EXCLUDED.latest_commit_sha, updated_at = NOW()
RETURNING *;

-- name: DeleteRef :exec
DELETE FROM refs WHERE id = $1;