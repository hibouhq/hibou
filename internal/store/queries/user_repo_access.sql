-- name: UpsertForgeUserRepoAccess :exec
INSERT INTO user_repo_access (user_id, repo_id, role, source, synced_at, updated_at)
VALUES ($1, $2, $3, 'forge', NOW(), NOW())
ON CONFLICT (user_id, repo_id) DO UPDATE
SET role = EXCLUDED.role,
    synced_at = NOW(),
    updated_at = NOW()
WHERE user_repo_access.source = 'forge';

-- name: PruneForgeUserRepoAccess :exec
DELETE FROM user_repo_access
WHERE user_id = $1
  AND source = 'forge'
  AND NOT (repo_id = ANY($2::uuid[]));

-- name: ListUserRepoAccess :many
SELECT user_id, repo_id, role, source, synced_at, created_at, updated_at
FROM user_repo_access
WHERE user_id = $1;