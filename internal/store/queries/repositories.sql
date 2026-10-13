-- name: CreateRepository :one
INSERT INTO repositories (org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at;

-- name: GetRepositoryByID :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
FROM repositories
WHERE id = $1;

-- name: GetRepositoryBySlug :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
FROM repositories
WHERE org_id = $1 AND slug = $2;

-- name: GetRepositoryBySlugAndOrg :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
FROM repositories
WHERE slug = $1 AND org_id = $2;

-- name: GetRepositoryByProviderID :one
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
FROM repositories
WHERE org_id = $1 AND provider = $2 AND provider_id = $3;

-- name: ListRepositoriesByOrg :many
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
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
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
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
RETURNING id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at;

-- name: SyncRepositoryDefaultBranch :many
-- The forge is the source of truth for the default branch: every enrolled
-- repository tracking this forge repo follows it. provider_id is matched
-- case-insensitively because it stores the forge's canonical provider key.
UPDATE repositories
SET default_branch = sqlc.arg(default_branch), updated_at = NOW()
WHERE provider = sqlc.arg(provider)
  AND lower(provider_id) = lower(sqlc.arg(provider_key))
  AND default_branch <> sqlc.arg(default_branch)
RETURNING id, org_id, slug, default_branch;

-- name: ListRepositoryRetentionUsage :many
SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
FROM repositories
WHERE retention_artifact_bytes > 0
ORDER BY retention_artifact_bytes DESC, id ASC;

-- name: ListRepositoriesForRetention :many
SELECT DISTINCT repo.id, repo.org_id, repo.team_id, repo.name, repo.slug, repo.provider, repo.provider_id, repo.default_branch, repo.sync_state, repo.retention_artifact_bytes, repo.created_at, repo.updated_at
FROM repositories repo
JOIN refs r ON r.repo_id = repo.id
JOIN snapshots s ON s.ref_id = r.id
WHERE s.status != 'purged'
ORDER BY repo.id ASC;

-- name: DeleteRepository :exec
DELETE FROM repositories WHERE id = $1;

-- name: ListRepositoryIDsByOrg :many
SELECT id FROM repositories WHERE org_id = $1;
