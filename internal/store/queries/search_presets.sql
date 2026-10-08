-- name: ListUserSearchPresets :many
SELECT id, owner_user_id, scope_type, scope_id, surface, name, query, created_at, updated_at
FROM search_presets
WHERE owner_user_id = $1 AND scope_type = 'user' AND surface = $2
ORDER BY lower(name);

-- name: CountUserSearchPresets :one
SELECT count(*)
FROM search_presets
WHERE owner_user_id = $1 AND scope_type = 'user' AND surface = $2;

-- name: CreateUserSearchPreset :one
INSERT INTO search_presets (owner_user_id, surface, name, query)
VALUES ($1, $2, $3, $4)
RETURNING id, owner_user_id, scope_type, scope_id, surface, name, query, created_at, updated_at;

-- name: UpdateUserSearchPreset :one
UPDATE search_presets
SET name = $3, query = $4, updated_at = now()
WHERE id = $1 AND owner_user_id = $2 AND scope_type = 'user'
RETURNING id, owner_user_id, scope_type, scope_id, surface, name, query, created_at, updated_at;

-- name: DeleteUserSearchPreset :execrows
DELETE FROM search_presets
WHERE id = $1 AND owner_user_id = $2 AND scope_type = 'user';
