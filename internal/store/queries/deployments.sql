-- name: CreateDeployment :one
INSERT INTO deployments (client_id, release_id, environment, status, deployed_at, deployed_by, rollback_target_id, notes)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetDeploymentByID :one
SELECT * FROM deployments WHERE id = $1;

-- name: ListDeploymentsByClient :many
SELECT * FROM deployments WHERE client_id = $1 ORDER BY deployed_at DESC LIMIT $2 OFFSET $3;

-- name: ListDeploymentsWithReleaseByClient :many
SELECT
	d.*,
	r.version AS release_version
FROM deployments d
LEFT JOIN releases r ON r.id = d.release_id
WHERE d.client_id = $1
ORDER BY d.deployed_at DESC
LIMIT $2 OFFSET $3;

-- name: CountDeploymentsByClient :one
SELECT COUNT(*)::bigint FROM deployments WHERE client_id = $1;

-- name: ListDeploymentsByRelease :many
SELECT * FROM deployments WHERE release_id = $1 ORDER BY deployed_at DESC LIMIT $2 OFFSET $3;

-- name: CountDeploymentsByRelease :one
SELECT COUNT(*)::bigint FROM deployments WHERE release_id = $1;

-- name: UpdateDeploymentStatus :one
UPDATE deployments SET status = $2 WHERE id = $1 RETURNING *;

-- name: ListActiveDeploymentsByClient :many
SELECT * FROM deployments WHERE client_id = $1 AND status = 'active' ORDER BY deployed_at DESC;

-- name: SupersedeActiveDeployments :execrows
-- Release-side rollout semantics (ADR-024 §4): giving a client a new release
-- of a repo supersedes its active deployment of any other release of that
-- repo in the same environment.
UPDATE deployments d
SET status = 'superseded'
FROM releases r
WHERE d.release_id = r.id
  AND r.repo_id = $1
  AND d.client_id = $2
  AND d.environment = $3
  AND d.status = 'active'
  AND d.release_id <> $4;

-- name: CountActiveDeploymentsByRelease :one
SELECT COUNT(*)::bigint FROM deployments WHERE release_id = $1 AND status = 'active';

-- name: GetDeploymentByReleaseAndID :one
SELECT * FROM deployments WHERE release_id = $1 AND id = $2;
