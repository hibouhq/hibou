-- name: CreateOrganization :one
INSERT INTO organizations (name, slug, display_name, provider)
VALUES ($1, $2, $3, $4)
RETURNING id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login;

-- name: GetOrganizationByID :one
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login
FROM organizations
WHERE id = $1;

-- name: GetOrganizationByProviderAndSlug :one
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login
FROM organizations
WHERE provider = $1 AND slug = $2;

-- name: ListOrganizations :many
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login
FROM organizations
ORDER BY name ASC;

-- name: ListOrganizationsByUser :many
SELECT o.id, o.name, o.slug, o.display_name, o.provider, o.settings, o.created_at, o.updated_at, o.forge_account_id, o.forge_account_login
FROM organizations o
WHERE o.id IN (
    SELECT org_id FROM org_members WHERE user_id = $1
)
ORDER BY o.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountOrganizationsByUser :one
SELECT COUNT(*)::bigint
FROM organizations
WHERE id IN (
    SELECT org_id FROM org_members WHERE user_id = $1
);

-- name: UpdateOrganization :one
UPDATE organizations
SET name = $2, display_name = $3, updated_at = NOW()
WHERE id = $1
RETURNING id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login;

-- name: UpdateOrganizationSettings :one
UPDATE organizations
SET settings = $2, updated_at = NOW()
WHERE id = $1
RETURNING id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login;

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE id = $1;

-- name: GetOrganizationByForgeAccountID :one
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at, forge_account_id, forge_account_login
FROM organizations
WHERE provider = $1 AND forge_account_id = $2;

-- name: SetOrganizationForgeAccount :exec
-- Binds the org to its forge account. The id is write-once: an org already
-- bound to a different account id is never rebound (the WHERE guard).
UPDATE organizations
SET forge_account_id = COALESCE(sqlc.narg(account_id), forge_account_id),
    forge_account_login = sqlc.arg(account_login),
    updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND (forge_account_id IS NULL OR sqlc.narg(account_id)::text IS NULL OR forge_account_id = sqlc.narg(account_id));
