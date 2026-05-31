-- name: CreateOrganization :one
INSERT INTO organizations (name, slug, display_name, provider)
VALUES ($1, $2, $3, $4)
RETURNING id, name, slug, display_name, provider, settings, created_at, updated_at;

-- name: GetOrganizationByID :one
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at
FROM organizations
WHERE id = $1;

-- name: GetOrganizationByProviderAndSlug :one
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at
FROM organizations
WHERE provider = $1 AND slug = $2;

-- name: ListOrganizations :many
SELECT id, name, slug, display_name, provider, settings, created_at, updated_at
FROM organizations
ORDER BY name ASC;

-- name: ListOrganizationsByUser :many
SELECT o.id, o.name, o.slug, o.display_name, o.provider, o.settings, o.created_at, o.updated_at
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
RETURNING id, name, slug, display_name, provider, settings, created_at, updated_at;

-- name: UpdateOrganizationSettings :one
UPDATE organizations
SET settings = $2, updated_at = NOW()
WHERE id = $1
RETURNING id, name, slug, display_name, provider, settings, created_at, updated_at;

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE id = $1;
