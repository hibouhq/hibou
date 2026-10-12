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
-- A forge-synced non-admin membership is repo-scoped when the last sync gave
-- the user access to some of the org's repositories but not to one that was
-- already enrolled at that time: that is the forge saying "these repositories,
-- not the organization". Members whose sync covered every repository (the
-- forge's own org-wide read), invited members and admins are never scoped.
WITH access AS (
    SELECT ura.repo_id, COALESCE(ura.synced_at, ura.updated_at) AS seen_at
    FROM user_repo_access ura
    JOIN repositories r ON r.id = ura.repo_id
    WHERE ura.user_id = sqlc.arg(user_id)
      AND r.org_id = sqlc.arg(org_id)
)
SELECT (
    EXISTS (
        SELECT 1
        FROM org_members om
        WHERE om.org_id = sqlc.arg(org_id)
          AND om.user_id = sqlc.arg(user_id)
          AND om.source = 'forge'
          AND om.role IN ('viewer', 'developer')
    )
    AND EXISTS (
        SELECT 1
        FROM repositories r
        WHERE r.org_id = sqlc.arg(org_id)
          AND r.created_at <= (SELECT MAX(seen_at) FROM access)
          AND NOT EXISTS (SELECT 1 FROM access a WHERE a.repo_id = r.id)
    )
)::boolean AS repo_scoped;

-- name: ListRepoAudienceUserIDs :many
-- Org members who may see a repository, for targeting live events. Repository
-- collaborators (forge viewer/developer memberships that carry per-repository
-- grants in this org) are included only with a grant on this repository. A
-- member whose sync predates the repository may be left out; live events are
-- best-effort and the page still polls, so erring narrow is the safe side.
SELECT om.user_id
FROM org_members om
JOIN repositories repo ON repo.org_id = om.org_id
WHERE repo.id = sqlc.arg(repo_id)
  AND (
      om.source <> 'forge'
      OR om.role NOT IN ('viewer', 'developer')
      OR EXISTS (
          SELECT 1 FROM user_repo_access ura
          WHERE ura.user_id = om.user_id AND ura.repo_id = repo.id
      )
      OR NOT EXISTS (
          SELECT 1
          FROM user_repo_access ura
          JOIN repositories other ON other.id = ura.repo_id
          WHERE ura.user_id = om.user_id AND other.org_id = om.org_id
      )
  );
