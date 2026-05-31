-- name: CreateLicensePolicy :one
INSERT INTO license_policies (
    org_id,
    name,
    allowed_licenses,
    denied_licenses,
    enabled
)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetLicensePolicyByID :one
SELECT * FROM license_policies WHERE id = $1;

-- name: ListLicensePoliciesByOrg :many
SELECT * FROM license_policies WHERE org_id = $1 ORDER BY name ASC;

-- name: UpdateLicensePolicy :one
UPDATE license_policies
SET name = $2,
    allowed_licenses = $3,
    denied_licenses = $4,
    enabled = $5,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteLicensePolicy :exec
DELETE FROM license_policies WHERE id = $1;

-- name: CreateLicenseException :one
INSERT INTO license_exceptions (
    policy_id,
    component_purl,
    license_id,
    justification,
    expires_at,
    created_by
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListLicenseExceptionsByPolicy :many
SELECT * FROM license_exceptions WHERE policy_id = $1 ORDER BY created_at DESC;

-- name: DeleteLicenseException :exec
DELETE FROM license_exceptions WHERE id = $1;
