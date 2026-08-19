-- name: GetInstanceSetting :one
SELECT * FROM instance_settings WHERE key = $1;

-- name: UpsertInstanceSetting :one
INSERT INTO instance_settings (key, value, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
RETURNING *;
