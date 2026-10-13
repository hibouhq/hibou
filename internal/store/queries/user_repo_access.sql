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

-- name: ListUserRepoAccessInOrg :many
SELECT ura.repo_id, ura.role
FROM user_repo_access ura
JOIN repositories r ON r.id = ura.repo_id
WHERE ura.user_id = sqlc.arg(user_id)
  AND r.org_id = sqlc.arg(org_id);

-- name: IsRepoScopedOrgMember :one
-- Recorded by the permission sync (org_members.repo_scoped). A scoped member
-- sees exactly their user_repo_access rows, so a repository enrolled after the
-- last sync, or the deletion of their only granted repository, leaves them
-- with less, never with the whole organization. A forge viewer/developer
-- recorded as org-wide becomes scoped once a repository enrolled after their
-- verdict (repo_scope_at) has no grant of theirs: the forge never said they
-- may see it.
SELECT EXISTS (
    SELECT 1
    FROM org_members om
    WHERE om.org_id = sqlc.arg(org_id)
      AND om.user_id = sqlc.arg(user_id)
      AND (
          om.repo_scoped
          OR (
              om.source = 'forge'
              AND om.role IN ('viewer', 'developer')
              AND om.repo_scope_at IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM repositories r
                  WHERE r.org_id = om.org_id
                    AND r.created_at > om.repo_scope_at
                    AND NOT EXISTS (
                        SELECT 1 FROM user_repo_access ura
                        WHERE ura.user_id = om.user_id AND ura.repo_id = r.id
                    )
              )
          )
      )
)::boolean AS repo_scoped;

-- name: DeleteForgeUserRepoAccessInOrg :exec
DELETE FROM user_repo_access ura
USING repositories r
WHERE r.id = ura.repo_id
  AND ura.user_id = sqlc.arg(user_id)
  AND r.org_id = sqlc.arg(org_id)
  AND ura.source = 'forge';

-- name: ListRepoAudienceUserIDs :many
-- Org members who may see a repository, for targeting live events.
-- Repository-scoped members are included only with a grant on it, and so
-- are forge viewers/developers whose verdict predates a repository they hold
-- no grant on (see IsRepoScopedOrgMember).
SELECT om.user_id
FROM org_members om
JOIN repositories repo ON repo.org_id = om.org_id
WHERE repo.id = sqlc.arg(repo_id)
  AND (
      EXISTS (
          SELECT 1 FROM user_repo_access ura
          WHERE ura.user_id = om.user_id AND ura.repo_id = repo.id
      )
      OR (
          NOT om.repo_scoped
          AND NOT (
              om.source = 'forge'
              AND om.role IN ('viewer', 'developer')
              AND om.repo_scope_at IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM repositories r
                  WHERE r.org_id = om.org_id
                    AND r.created_at > om.repo_scope_at
                    AND NOT EXISTS (
                        SELECT 1 FROM user_repo_access g
                        WHERE g.user_id = om.user_id AND g.repo_id = r.id
                    )
              )
          )
      )
  );
