-- name: CreateRepository :one
INSERT INTO repositories (org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at;

-- name: GetRepositoryByID :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at
FROM repositories
WHERE id = $1;

-- name: GetRepositoryBySlug :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at
FROM repositories
WHERE org_id = $1 AND slug = $2;

-- name: GetRepositoryBySlugAndOrg :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at
FROM repositories
WHERE slug = $1 AND org_id = $2;

-- name: GetRepositoryByProviderID :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at
FROM repositories
WHERE org_id = $1 AND provider = $2 AND provider_id = $3;

-- name: ListRepositoriesByOrg :many
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at
FROM repositories
WHERE org_id = $1
ORDER BY name ASC
LIMIT $2 OFFSET $3;

-- name: CountRepositoriesByOrg :one
SELECT COUNT(*)::bigint FROM repositories WHERE org_id = $1;

-- name: ListRepositoriesByTeam :many
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at
FROM repositories
WHERE team_id = $1
ORDER BY name ASC
LIMIT $2 OFFSET $3;

-- name: CountRepositoriesByTeam :one
SELECT COUNT(*)::bigint FROM repositories WHERE team_id = $1;

-- name: UpdateRepository :one
UPDATE repositories
SET name = $2, slug = $3, default_branch = $4, sync_state = $5, team_id = $6, updated_at = NOW()
WHERE id = $1
RETURNING id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, created_at, updated_at;

-- name: DeleteRepository :exec
DELETE FROM repositories WHERE id = $1;