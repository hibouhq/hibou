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

-- name: ListStaleRepositories :many
SELECT
	repo.id,
	repo.org_id,
	repo.team_id,
	repo.name,
	repo.slug,
	repo.default_branch,
	COALESCE(MAX(sc.completed_at), '1970-01-01T00:00:00Z'::timestamptz) AS last_scan_completed_at
FROM repositories repo
LEFT JOIN refs r ON r.repo_id = repo.id
LEFT JOIN snapshots s ON s.ref_id = r.id
LEFT JOIN scans sc ON sc.snapshot_id = s.id AND sc.status = 'complete'
GROUP BY repo.id, repo.org_id, repo.team_id, repo.name, repo.slug, repo.default_branch
HAVING COALESCE(MAX(sc.completed_at), '1970-01-01T00:00:00Z'::timestamptz) < $1
ORDER BY last_scan_completed_at ASC, repo.name ASC;

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
