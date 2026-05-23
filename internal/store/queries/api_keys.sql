-- name: CreateAPIKey :one
INSERT INTO api_keys (user_id, name, key_hash, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at;

-- name: GetAPIKeyByHash :one
SELECT ak.id, ak.user_id, ak.name, ak.key_hash, ak.scopes, ak.expires_at, ak.last_used_at, ak.created_at,
    u.id AS owner_id, u.email, u.display_name, u.avatar_url, u.provider, u.provider_id, u.created_at AS user_created_at, u.updated_at AS user_updated_at
FROM api_keys ak
JOIN users u ON u.id = ak.user_id
WHERE ak.key_hash = $1;

-- name: ListAPIKeysByUser :many
SELECT id, user_id, name, key_hash, scopes, expires_at, last_used_at, created_at
FROM api_keys
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: DeleteAPIKey :exec
DELETE FROM api_keys
WHERE id = $1 AND user_id = $2;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys
SET last_used_at = NOW()
WHERE id = $1;