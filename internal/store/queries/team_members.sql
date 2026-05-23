-- name: AddTeamMember :exec
INSERT INTO team_members (team_id, user_id, role)
VALUES ($1, $2, $3);

-- name: RemoveTeamMember :exec
DELETE FROM team_members
WHERE team_id = $1 AND user_id = $2;

-- name: ListTeamMembers :many
SELECT tm.team_id, tm.user_id, tm.role, tm.created_at,
    u.id AS user_id_2, u.email, u.display_name, u.avatar_url, u.provider, u.provider_id, u.created_at AS user_created_at, u.updated_at AS user_updated_at
FROM team_members tm
JOIN users u ON u.id = tm.user_id
WHERE tm.team_id = $1
ORDER BY tm.created_at ASC
LIMIT $2 OFFSET $3;

-- name: CountTeamMembers :one
SELECT COUNT(*)::bigint FROM team_members WHERE team_id = $1;

-- name: GetTeamMemberRole :one
SELECT role
FROM team_members
WHERE team_id = $1 AND user_id = $2;