-- name: UpsertNotShippedEntry :one
INSERT INTO not_shipped_entries (org_id, repo_id, pattern, reason, created_by)
VALUES (sqlc.arg(org_id), sqlc.narg(repo_id), sqlc.arg(pattern), sqlc.arg(reason), sqlc.narg(created_by))
ON CONFLICT (org_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), pattern) DO UPDATE SET
    reason = EXCLUDED.reason,
    created_by = EXCLUDED.created_by,
    created_at = now()
RETURNING *;

-- name: DeleteNotShippedEntry :execrows
DELETE FROM not_shipped_entries
WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id);

-- name: GetNotShippedEntry :one
SELECT * FROM not_shipped_entries WHERE id = sqlc.arg(id) AND org_id = sqlc.arg(org_id);

-- name: ListNotShippedEntries :many
-- Org-wide rows and, when a repository is given, its rows.
SELECT * FROM not_shipped_entries
WHERE org_id = sqlc.arg(org_id)
    AND (repo_id IS NULL OR repo_id = sqlc.narg(repo_id))
ORDER BY repo_id NULLS FIRST, created_at DESC;
