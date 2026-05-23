-- name: AddOrgMember :exec
INSERT INTO org_members (org_id, user_id, role)
VALUES ($1, $2, $3);

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

-- name: GetOrgMemberRole :one
SELECT role
FROM org_members
WHERE org_id = $1 AND user_id = $2;