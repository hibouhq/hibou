-- name: CreateTeam :one
INSERT INTO teams (org_id, name, slug)
VALUES ($1, $2, $3)
RETURNING id, org_id, name, slug, created_at, updated_at;

-- name: GetTeamByID :one
SELECT id, org_id, name, slug, created_at, updated_at
FROM teams
WHERE id = $1;

-- name: GetTeamBySlug :one
SELECT id, org_id, name, slug, created_at, updated_at
FROM teams
WHERE org_id = $1 AND slug = $2;

-- name: ListTeamsByOrg :many
SELECT id, org_id, name, slug, created_at, updated_at
FROM teams
WHERE org_id = $1
ORDER BY created_at ASC
LIMIT $2 OFFSET $3;

-- name: CountTeamsByOrg :one
SELECT COUNT(*)::bigint FROM teams WHERE org_id = $1;

-- name: UpdateTeam :one
UPDATE teams
SET name = $2, slug = $3, updated_at = NOW()
WHERE id = $1
RETURNING id, org_id, name, slug, created_at, updated_at;

-- name: DeleteTeam :exec
DELETE FROM teams WHERE id = $1;