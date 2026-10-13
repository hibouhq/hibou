-- name: AddOrgMember :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3);

-- name: UpsertOrgMemberRole :exec
-- An invite is org-wide by definition: it clears any repository scoping the
-- forge sync recorded.
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, source = 'invite', synced_at = NULL, repo_scoped = false;

-- name: RemoveOrgMember :exec
DELETE FROM org_members
WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgMembers :many
SELECT om.org_id, om.user_id, om.role, om.created_at, om.source,
    u.id AS user_id_2, u.email, u.display_name, u.avatar_url, u.provider, u.provider_id, u.created_at AS user_created_at, u.updated_at AS user_updated_at
FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1
ORDER BY om.created_at ASC
LIMIT $2 OFFSET $3;

-- name: CountOrgMembers :one
SELECT COUNT(*)::bigint FROM org_members WHERE org_id = $1;

-- name: CountOrgAdmins :one
SELECT COUNT(*)::bigint
FROM org_members
WHERE org_id = $1 AND role = 'admin';

-- name: GetOrgMemberRole :one
SELECT role
FROM org_members
WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgAdminIDs :many
SELECT user_id
FROM org_members
WHERE org_id = $1 AND role = 'admin';

-- name: UpsertForgeOrgMember :exec
-- repo_scoped is the sync's verdict that the forge grants this person
-- specific repositories rather than the organization (outside collaborators).
INSERT INTO org_members (org_id, user_id, role, source, synced_at, repo_scoped)
VALUES ($1, $2, $3, 'forge', NOW(), sqlc.arg(repo_scoped))
ON CONFLICT (org_id, user_id) DO UPDATE
SET role = EXCLUDED.role,
        synced_at = NOW(),
        repo_scoped = EXCLUDED.repo_scoped
WHERE org_members.source = 'forge';

-- name: PruneForgeOrgMembers :exec
DELETE FROM org_members
WHERE org_id = $1
    AND source = 'forge'
    AND NOT (user_id = ANY($2::uuid[]));

-- name: PruneForgeOrgMembersForUser :exec
DELETE FROM org_members
WHERE user_id = $1 AND source = 'forge' AND NOT (org_id = ANY($2::uuid[]));

-- name: ListForgeOrgMemberIDs :many
SELECT user_id
FROM org_members
WHERE org_id = $1 AND source = 'forge';

-- name: ListStaleForgeOrgMemberships :many
-- Forge-synced memberships not confirmed since stale_before, oldest first, for
-- the membership re-validation loop.
SELECT om.org_id, om.user_id, om.role, om.repo_scoped, om.synced_at,
    o.provider AS org_provider, o.slug AS org_slug, o.forge_account_login,
    u.provider AS user_provider, u.forge_login
FROM org_members om
JOIN organizations o ON o.id = om.org_id
JOIN users u ON u.id = om.user_id
WHERE om.source = 'forge'
  AND (om.synced_at IS NULL OR om.synced_at < sqlc.arg(stale_before))
ORDER BY om.synced_at ASC NULLS FIRST
LIMIT sqlc.arg(max_rows);

-- name: ListForgeOrgMemberLogins :many
-- Org-wide forge members with a known login, most recently confirmed first:
-- the re-validation loop asks the forge about one of them before trusting a
-- "not a member" answer about anyone else.
SELECT om.user_id, u.forge_login::text AS forge_login
FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = sqlc.arg(org_id)
  AND om.source = 'forge'
  AND NOT om.repo_scoped
  AND COALESCE(u.forge_login, '') <> ''
ORDER BY om.synced_at DESC NULLS LAST
LIMIT sqlc.arg(max_rows);

-- name: TouchForgeOrgMember :exec
UPDATE org_members
SET synced_at = NOW()
WHERE org_id = $1 AND user_id = $2 AND source = 'forge';

-- name: DeleteForgeOrgMember :exec
DELETE FROM org_members
WHERE org_id = $1 AND user_id = $2 AND source = 'forge';
