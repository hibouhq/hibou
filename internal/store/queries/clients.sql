-- name: CreateClient :one
INSERT INTO clients (org_id, name, slug, labels, client_type, contact_email, contact_name, notification_prefs, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetClientByID :one
SELECT * FROM clients WHERE id = $1;

-- name: GetClientBySlug :one
SELECT * FROM clients WHERE org_id = $1 AND slug = $2;

-- name: ListClientsByOrg :many
SELECT * FROM clients WHERE org_id = $1 ORDER BY name ASC LIMIT $2 OFFSET $3;

-- name: ListClientsWithStatsByOrg :many
SELECT
    c.*,
    COALESCE(stats.deployments_count, 0)::bigint AS deployments_count,
    stats.last_deployment_at,
    CASE
        WHEN active_release.version IS NULL THEN NULL
        ELSE active_release.version
    END AS active_version
FROM clients c
LEFT JOIN (
    SELECT
        client_id,
        COUNT(*)::bigint AS deployments_count,
        MAX(deployed_at) AS last_deployment_at
    FROM deployments
    GROUP BY client_id
) AS stats ON stats.client_id = c.id
LEFT JOIN LATERAL (
    SELECT r.version
    FROM deployments d
    JOIN releases r ON r.id = d.release_id
    WHERE d.client_id = c.id AND d.status = 'active'
    ORDER BY d.deployed_at DESC
    LIMIT 1
) AS active_release ON true
WHERE c.org_id = $1
ORDER BY c.name ASC
LIMIT $2 OFFSET $3;

-- name: CountClientsByOrg :one
SELECT COUNT(*)::bigint FROM clients WHERE org_id = $1;

-- name: ListClientImpactVulns :many
SELECT DISTINCT
    a.canonical_id,
    a.severity::text AS severity,
    c.name AS component_name,
    r.version AS release_version
FROM deployments d
JOIN releases r ON r.id = d.release_id
JOIN vuln_matches vm ON vm.snapshot_id = r.snapshot_id
JOIN advisories a ON a.id = vm.advisory_id
JOIN components c ON c.id = vm.component_id
WHERE d.client_id = $1
  AND d.status = 'active'
  AND r.snapshot_id IS NOT NULL
  AND vm.suppressed = FALSE
  AND vm.is_affected = TRUE;

-- name: UpdateClient :one
UPDATE clients
SET name = $2,
    labels = $3,
    client_type = $4,
    contact_email = $5,
    contact_name = $6,
    notification_prefs = $7,
    metadata = $8,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteClient :exec
DELETE FROM clients WHERE id = $1;

-- name: ListClientLabelKeys :many
SELECT DISTINCT jsonb_object_keys(labels) AS label_key FROM clients WHERE org_id = $1 ORDER BY 1;
