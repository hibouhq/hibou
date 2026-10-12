-- name: CreateUser :one
INSERT INTO users (email, display_name, provider, provider_id)
VALUES ($1, $2, $3, $4)
RETURNING id, email, display_name, avatar_url, provider, provider_id, created_at, updated_at, session_epoch;

-- name: GetUserByID :one
SELECT id, email, display_name, avatar_url, provider, provider_id, created_at, updated_at, session_epoch
FROM users
WHERE id = $1;

-- name: GetUserByProviderID :one
SELECT id, email, display_name, avatar_url, provider, provider_id, created_at, updated_at, session_epoch
FROM users
WHERE provider = $1 AND provider_id = $2;

-- name: UpsertUser :one
INSERT INTO users (email, display_name, avatar_url, provider, provider_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (provider, provider_id) DO UPDATE SET
	email = EXCLUDED.email,
	display_name = EXCLUDED.display_name,
	avatar_url = EXCLUDED.avatar_url,
	updated_at = NOW()
RETURNING id, email, display_name, avatar_url, provider, provider_id, created_at, updated_at, session_epoch;

-- name: UpdateUser :one
UPDATE users
SET email = $2, display_name = $3, avatar_url = $4, updated_at = NOW()
WHERE id = $1
RETURNING id, email, display_name, avatar_url, provider, provider_id, created_at, updated_at, session_epoch;

-- name: BumpUserSessionEpoch :one
-- Invalidates every session cookie issued to the user so far.
UPDATE users
SET session_epoch = session_epoch + 1
WHERE id = $1
RETURNING session_epoch;

-- name: CountOrgsCreatedByUser :one
-- Orgs the user holds a non-forge admin membership in: the creator's grant
-- from POST /orgs. Forge-synced memberships do not count against the cap.
SELECT count(*)
FROM org_members
WHERE user_id = $1 AND role = 'admin' AND source = 'invite';
