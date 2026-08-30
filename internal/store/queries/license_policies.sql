-- name: GetOrgLicensePolicy :one
-- The org's single active policy. A partial unique index guarantees at most one
-- enabled row per org, so this cannot be ambiguous.
SELECT * FROM license_policies WHERE org_id = $1 AND enabled ORDER BY updated_at DESC LIMIT 1;

-- name: UpsertOrgLicensePolicy :one
INSERT INTO license_policies (
    org_id,
    name,
    allowed_licenses,
    denied_licenses,
    denied_categories,
    exempt_purls,
    deny_unknown,
    evaluate,
    enabled,
    updated_by
)
VALUES (
    sqlc.arg(org_id),
    sqlc.arg(name),
    sqlc.arg(allowed_licenses),
    sqlc.arg(denied_licenses),
    sqlc.arg(denied_categories),
    sqlc.arg(exempt_purls),
    sqlc.arg(deny_unknown),
    sqlc.arg(evaluate),
    TRUE,
    sqlc.arg(updated_by)
)
-- Conflict on (org_id, name), the constraint the table has shipped with since
-- 00001. Targeting the partial enabled-index instead would miss a RETIRED row of
-- the same name and fail the insert against that older constraint. Re-enabling
-- here is deliberate: it revives the retired row rather than accumulating one
-- dead row per toggle. The history of who changed what lives in audit_logs.
ON CONFLICT (org_id, name) DO UPDATE SET
    enabled = TRUE,
    name = EXCLUDED.name,
    allowed_licenses = EXCLUDED.allowed_licenses,
    denied_licenses = EXCLUDED.denied_licenses,
    denied_categories = EXCLUDED.denied_categories,
    exempt_purls = EXCLUDED.exempt_purls,
    deny_unknown = EXCLUDED.deny_unknown,
    evaluate = EXCLUDED.evaluate,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW()
RETURNING *;

-- name: DisableOrgLicensePolicy :exec
-- Retire rather than delete: the row keeps its id and updated_by so the last
-- enforced policy is still inspectable, and re-enabling revives it. The change
-- history itself is in audit_logs.
UPDATE license_policies SET enabled = FALSE, updated_at = NOW(), updated_by = $2
WHERE org_id = $1 AND enabled;
