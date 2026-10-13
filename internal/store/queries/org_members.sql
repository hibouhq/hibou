-- name: AddOrgMember :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3);

-- name: UpsertOrgMemberRole :exec
-- An invite is org-wide by definition: it clears any repository scoping the
-- forge sync recorded.
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, source = 'invite', synced_at = NULL, repo_scoped = false, repo_scope_at = NULL;

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
-- repo_scope_at dates that verdict: repositories enrolled after it count
-- only through a grant (IsRepoScopedOrgMember). It is set an hour early so
-- a repository enrolled while the sync ran is never mistaken for one it saw;
-- the margin costs nothing, since such a repository matters only when the
-- member holds no grant on it.
INSERT INTO org_members (org_id, user_id, role, source, synced_at, repo_scoped, repo_scope_at)
VALUES ($1, $2, $3, 'forge', NOW(), sqlc.arg(repo_scoped), NOW() - interval '1 hour')
ON CONFLICT (org_id, user_id) DO UPDATE
SET role = EXCLUDED.role,
        synced_at = NOW(),
        repo_scoped = EXCLUDED.repo_scoped,
        repo_scope_at = EXCLUDED.repo_scope_at,
        revalidation_attempted_at = NULL
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
-- the membership re-validation loop. Rows the loop already attempted since
-- stale_before are left out, so undecidable rows cannot starve the rest.
SELECT om.org_id, om.user_id, om.role, om.repo_scoped, om.synced_at,
    o.provider AS org_provider, o.slug AS org_slug, o.forge_account_login, o.forge_account_id,
    u.provider AS user_provider, u.provider_id AS user_provider_id, u.forge_login
FROM org_members om
JOIN organizations o ON o.id = om.org_id
JOIN users u ON u.id = om.user_id
WHERE om.source = 'forge'
  AND (om.synced_at IS NULL OR om.synced_at < sqlc.arg(stale_before))
  AND (om.revalidation_attempted_at IS NULL OR om.revalidation_attempted_at < sqlc.arg(stale_before))
ORDER BY COALESCE(om.revalidation_attempted_at, om.synced_at) ASC NULLS FIRST
LIMIT sqlc.arg(max_rows);

-- name: MarkForgeOrgMemberRevalidationAttempted :exec
UPDATE org_members
SET revalidation_attempted_at = NOW()
WHERE org_id = $1 AND user_id = $2 AND source = 'forge';

-- name: ListForgeOrgMemberForgeIDs :many
-- Org-wide forge members with a known login, most recently confirmed first,
-- by immutable forge user id: the re-validation loop asks the forge about one
-- of them before trusting a "not a member" answer about anyone else.
SELECT om.user_id, u.provider_id
FROM org_members om
JOIN organizations o ON o.id = om.org_id
JOIN users u ON u.id = om.user_id
WHERE om.org_id = sqlc.arg(org_id)
  AND om.source = 'forge'
  AND NOT om.repo_scoped
  AND u.provider = o.provider
  AND COALESCE(u.forge_login, '') <> ''
ORDER BY om.synced_at DESC NULLS LAST
LIMIT sqlc.arg(max_rows);

-- name: ListUngrantedLateRepoMembers :many
-- Forge viewers/developers recorded as org-wide who hold no grant on a
-- repository enrolled after their verdict (repo_scope_at). Until the forge is
-- asked, IsRepoScopedOrgMember scopes them; the permission sync asks with the
-- installation token and grants the repository or records the scope. Random
-- order: pairs the forge cannot answer must not starve the rest.
SELECT om.org_id, om.user_id, om.role,
    o.provider AS org_provider, o.forge_account_id,
    u.provider AS user_provider, u.provider_id AS user_provider_id,
    r.id AS repo_id, r.slug AS repo_slug
FROM org_members om
JOIN organizations o ON o.id = om.org_id
JOIN users u ON u.id = om.user_id
JOIN repositories r ON r.org_id = om.org_id AND r.created_at > om.repo_scope_at
WHERE om.source = 'forge'
  AND om.role IN ('viewer', 'developer')
  AND NOT om.repo_scoped
  AND om.repo_scope_at IS NOT NULL
  AND COALESCE(o.forge_account_id, '') <> ''
  AND COALESCE(u.forge_login, '') <> ''
  AND NOT EXISTS (
      SELECT 1 FROM user_repo_access ura
      WHERE ura.user_id = om.user_id AND ura.repo_id = r.id
  )
ORDER BY random()
LIMIT sqlc.arg(max_rows);

-- name: SetForgeOrgMemberRepoScoped :exec
-- The forge withheld a repository from this member: record the verdict.
UPDATE org_members
SET repo_scoped = true
WHERE org_id = $1 AND user_id = $2 AND source = 'forge';

-- name: TouchForgeOrgMember :exec
UPDATE org_members
SET synced_at = NOW()
WHERE org_id = $1 AND user_id = $2 AND source = 'forge';

-- name: DeleteForgeOrgMember :exec
DELETE FROM org_members
WHERE org_id = $1 AND user_id = $2 AND source = 'forge';

-- name: ListOrgAdminIdentities :many
-- The forge identities (immutable provider ids) of an org's admins.
SELECT u.provider, u.provider_id
FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1 AND om.role = 'admin'
ORDER BY om.created_at ASC;
