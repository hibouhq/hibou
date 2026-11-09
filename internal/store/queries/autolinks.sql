-- Autolink references (ADR-053): prefixes an organisation turns into links
-- wherever people write, like a tracker's issue keys.

-- name: ListOrgAutolinks :many
SELECT * FROM org_autolinks WHERE org_id = $1 ORDER BY prefix;

-- name: CreateOrgAutolink :one
INSERT INTO org_autolinks (org_id, prefix, url_template, alphanumeric, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: DeleteOrgAutolink :execrows
DELETE FROM org_autolinks WHERE id = $1 AND org_id = $2;
