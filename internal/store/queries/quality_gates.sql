-- name: CreateQualityGate :one
INSERT INTO quality_gates (
    org_id,
    repo_id,
    name,
    description,
    max_critical,
    max_high,
    max_medium,
    max_new_findings,
    finding_severities,
    enabled
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetQualityGateByID :one
SELECT *
FROM quality_gates
WHERE id = $1;

-- name: ListQualityGatesByOrg :many
SELECT *
FROM quality_gates
WHERE org_id = $1
ORDER BY name ASC;

-- name: ListOrgWideQualityGates :many
SELECT *
FROM quality_gates
WHERE org_id = $1 AND repo_id IS NULL AND enabled = TRUE
ORDER BY name ASC;

-- name: ListQualityGatesByRepo :many
SELECT *
FROM quality_gates
WHERE repo_id = $1
ORDER BY name ASC;