-- name: CreateIntegration :one
INSERT INTO integrations (org_id, name, integration_type, config, enabled)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetIntegrationByID :one
SELECT * FROM integrations WHERE id = $1;

-- name: ListIntegrationsByOrg :many
SELECT * FROM integrations WHERE org_id = $1 ORDER BY name;

-- name: UpdateIntegration :one
UPDATE integrations SET name = $2, config = $3, enabled = $4, updated_at = NOW()
WHERE id = $1 RETURNING *;

-- name: UpdateIntegrationHealth :exec
UPDATE integrations SET last_success_at = $2, last_failure_at = $3, failure_count = $4, updated_at = NOW()
WHERE id = $1;

-- name: DeleteIntegration :exec
DELETE FROM integrations WHERE id = $1;