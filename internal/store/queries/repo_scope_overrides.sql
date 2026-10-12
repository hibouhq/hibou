-- name: ListRepoScopeOverrides :many
SELECT * FROM repo_scope_overrides WHERE repo_id = $1 ORDER BY kind, path;

-- name: CreateRepoScopeOverride :one
INSERT INTO repo_scope_overrides (repo_id, kind, path, reason, created_by)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (repo_id, kind, path) DO UPDATE SET reason = EXCLUDED.reason, created_by = EXCLUDED.created_by
RETURNING *;

-- name: DeleteRepoScopeOverride :execrows
DELETE FROM repo_scope_overrides WHERE id = $1 AND repo_id = $2;
