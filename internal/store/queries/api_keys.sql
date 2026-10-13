-- name: CreateAPIKey :one
INSERT INTO api_keys (user_id, name, key_hash, scopes, expires_at, owner_type, owner_id, description, approval_status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;

-- name: GetAPIKeyByHash :one
-- LEFT JOIN: an org-owned key is a service principal (ADR-022) and must
-- resolve even after its creating user is deleted; the auth layer rejects
-- user-owned keys whose user is gone.
SELECT ak.id, ak.user_id, ak.name, ak.key_hash, ak.scopes, ak.expires_at, ak.owner_type, ak.owner_id, ak.description, ak.last_used_at, ak.created_at, ak.approval_status, ak.approved_by, ak.approved_at,
    u.id AS actor_user_id, u.email, u.display_name, u.avatar_url, u.provider, u.provider_id, u.created_at AS user_created_at, u.updated_at AS user_updated_at,
    u.forge_login, u.signin_allowed_at,
    -- An org-owned key whose creator still exists but no longer belongs to
    -- the org stops authenticating: the person who holds the secret left.
    (ak.owner_type <> 'org' OR ak.user_id IS NULL OR u.id IS NULL OR EXISTS (
        SELECT 1 FROM org_members om WHERE om.org_id = ak.owner_id AND om.user_id = ak.user_id
    ))::boolean AS creator_membership_valid
FROM api_keys ak
LEFT JOIN users u ON u.id = ak.user_id
WHERE ak.key_hash = $1;

-- name: ListAPIKeysByUser :many
SELECT id, user_id, name, key_hash, scopes, expires_at, owner_type, owner_id, description, last_used_at, created_at, approval_status, approved_by, approved_at
FROM api_keys
WHERE user_id = $1 AND owner_type = 'user'
ORDER BY created_at DESC;

-- name: ListAPIKeysByOrg :many
-- The creator's name rides along so the review UI can show who requested a
-- pending token (LEFT JOIN: the creator may be deleted, the key survives).
SELECT ak.id, ak.user_id, ak.name, ak.key_hash, ak.scopes, ak.expires_at, ak.owner_type, ak.owner_id, ak.description, ak.last_used_at, ak.created_at, ak.approval_status, ak.approved_by, ak.approved_at,
    COALESCE(u.display_name, u.email, '') AS creator_display
FROM api_keys ak
LEFT JOIN users u ON u.id = ak.user_id
WHERE ak.owner_type = 'org' AND ak.owner_id = $1
ORDER BY ak.created_at DESC;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys
WHERE id = $1 AND user_id = $2 AND owner_type = 'user';

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = NOW()
WHERE id = $1;

-- name: GetAPIKeyByID :one
SELECT id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at
FROM api_keys
WHERE id = $1 AND user_id = $2 AND owner_type = 'user';

-- name: UpdateAPIKeyMeta :one
UPDATE api_keys
SET name = $3, description = $4, scopes = $5, expires_at = $6
WHERE id = $1 AND user_id = $2 AND owner_type = 'user'
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;

-- name: RotateAPIKey :one
UPDATE api_keys
SET key_hash = $3, last_used_at = NULL
WHERE id = $1 AND user_id = $2 AND owner_type = 'user'
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;

-- name: GetAPIKeyByOrg :one
SELECT id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at
FROM api_keys
WHERE id = $1 AND owner_type = 'org' AND owner_id = $2;

-- name: UpdateAPIKeyMetaByOrg :one
UPDATE api_keys
SET name = $3, description = $4, scopes = $5, expires_at = $6, approval_status = $7
WHERE id = $1 AND owner_type = 'org' AND owner_id = $2
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;

-- name: SetAPIKeyApprovalByOrg :one
-- ADR-022 amendment: an org admin's approve/reject decision on a
-- member-requested token. Approval is what makes the token authenticate.
UPDATE api_keys
SET approval_status = $3, approved_by = $4, approved_at = NOW()
WHERE id = $1 AND owner_type = 'org' AND owner_id = $2
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;

-- name: RotateAPIKeyByOrg :one
UPDATE api_keys
SET key_hash = $3, last_used_at = NULL
WHERE id = $1 AND owner_type = 'org' AND owner_id = $2
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;

-- name: DeleteAPIKeyByOrg :execrows
DELETE FROM api_keys
WHERE id = $1 AND owner_type = 'org' AND owner_id = $2;

-- name: ListUnscopedAPIKeysByOrgMembers :many
SELECT DISTINCT ak.id, ak.name, ak.expires_at, ak.last_used_at, ak.created_at,
    u.id AS member_id, u.display_name AS member_display, u.email AS member_email
FROM api_keys ak
JOIN users u ON u.id = ak.user_id
JOIN org_members om ON om.user_id = ak.user_id AND om.org_id = $1
WHERE ak.owner_type = 'user' AND ak.scopes = 'null'::jsonb
ORDER BY ak.last_used_at DESC NULLS LAST, ak.created_at DESC;

-- name: ListAPIKeysExpiringBefore :many
SELECT id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at
FROM api_keys
WHERE expires_at IS NOT NULL AND expires_at > NOW() AND expires_at <= $1
ORDER BY expires_at ASC;

-- name: CountAPIKeysCreatedByUser :one
-- Every key the user minted, personal or requested for an org: the per-user
-- cap counts what one account can create, whoever ends up owning it.
SELECT count(*)
FROM api_keys
WHERE user_id = $1;

-- name: DeleteAPIKeyByID :one
-- A token revoking itself (ADR-043 §6, logout). Only user-owned keys: an
-- org-owned service principal is revoked by an org admin.
DELETE FROM api_keys
WHERE id = $1 AND owner_type = 'user'
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at, owner_type, owner_id, description, approval_status, approved_by, approved_at;
