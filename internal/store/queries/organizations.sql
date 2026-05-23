-- name: CreateOrganization :one
INSERT INTO organizations (name, slug, display_name)
VALUES ($1, $2, $3)
RETURNING id, name, slug, display_name, settings, created_at, updated_at;

-- name: GetOrganizationByID :one
SELECT id, name, slug, display_name, settings, created_at, updated_at
FROM organizations
WHERE id = $1;

-- name: GetOrganizationBySlug :one
SELECT id, name, slug, display_name, settings, created_at, updated_at
FROM organizations
WHERE slug = $1;

-- name: ListOrganizationsByUser :many
SELECT o.id, o.name, o.slug, o.display_name, o.settings, o.created_at, o.updated_at
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
RETURNING id, name, slug, display_name, settings, created_at, updated_at;

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE id = $1;