-- name: AddOrgMember :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3);

-- name: UpsertOrgMemberRole :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, source = 'invite', synced_at = NULL;

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
INSERT INTO org_members (org_id, user_id, role, source, synced_at)
VALUES ($1, $2, $3, 'forge', NOW())
ON CONFLICT (org_id, user_id) DO UPDATE
SET role = EXCLUDED.role,
        synced_at = NOW()
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
