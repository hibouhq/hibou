-- name: UpsertForgeOrgAdmin :one
INSERT INTO forge_org_admins (
    provider,
    account,
    provider_user_id
)
VALUES ($1, $2, $3)
ON CONFLICT (provider, account, provider_user_id) DO UPDATE
SET updated_at = NOW()
RETURNING id, provider, account, provider_user_id, org_id, granted, created_at, updated_at;

-- name: SetForgeOrgAdminOrg :exec
UPDATE forge_org_admins
SET org_id = $4, updated_at = NOW()
WHERE provider = $1 AND account = $2 AND provider_user_id = $3;

-- name: MarkForgeOrgAdminGranted :exec
UPDATE forge_org_admins
SET granted = TRUE, updated_at = NOW()
WHERE id = $1;

-- name: ListPendingForgeOrgAdminsByUser :many
SELECT id, provider, account, provider_user_id, org_id, granted, created_at, updated_at
FROM forge_org_admins
WHERE provider = $1 AND provider_user_id = $2 AND org_id IS NOT NULL AND granted = FALSE
ORDER BY created_at ASC;

-- name: ListForgeOrgAdminsByUser :many
SELECT id, provider, account, provider_user_id, org_id, granted, created_at, updated_at
FROM forge_org_admins
WHERE provider = $1 AND provider_user_id = $2
ORDER BY account ASC, created_at ASC;

-- name: GetForgeOrgAdmin :one
SELECT id, provider, account, provider_user_id, org_id, granted, created_at, updated_at
FROM forge_org_admins
WHERE provider = $1 AND account = $2 AND provider_user_id = $3;

-- name: ForgeOrgAdminBindingExists :one
SELECT EXISTS(
    SELECT 1
    FROM forge_org_admins
    WHERE provider = $1 AND org_id = $2
) AS exists;

-- name: DeleteForgeOrgAdminsByAccount :many
-- An uninstalled or suspended App no longer proves anyone administers the
-- account: drop the bindings so pending claims cannot be redeemed later.
DELETE FROM forge_org_admins
WHERE provider = $1 AND account = $2
RETURNING id, provider, account, provider_user_id, org_id, granted, created_at, updated_at;
