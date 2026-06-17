-- name: AddOrgMember :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3);

-- name: UpsertOrgMemberRole :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- name: RemoveOrgMember :exec
DELETE FROM org_members
WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgMembers :many
SELECT om.org_id, om.user_id, om.role, om.created_at,
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
