-- name: UpsertForgeRepository :one
WITH prev AS (
    SELECT removed_at
    FROM forge_repositories
    WHERE provider = $1 AND provider_key = $8
)
INSERT INTO forge_repositories (
    provider,
    installation_id,
    provider_repo_id,
    account_login,
    owner,
    name,
    full_name,
    provider_key,
    private,
    default_branch,
    html_url,
    archived
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (provider, provider_key) DO UPDATE
SET installation_id = COALESCE(EXCLUDED.installation_id, forge_repositories.installation_id),
    provider_repo_id = COALESCE(NULLIF(EXCLUDED.provider_repo_id, ''), forge_repositories.provider_repo_id),
    account_login = EXCLUDED.account_login,
    owner = EXCLUDED.owner,
    name = EXCLUDED.name,
    full_name = EXCLUDED.full_name,
    -- GitHub's slim installation payloads still carry the real private bit, so generic upserts can keep owning it.
    private = EXCLUDED.private,
    default_branch = COALESCE(NULLIF(EXCLUDED.default_branch, ''), forge_repositories.default_branch),
    html_url = COALESCE(NULLIF(EXCLUDED.html_url, ''), forge_repositories.html_url),
    archived = forge_repositories.archived,
    last_seen_at = NOW(),
    updated_at = NOW(),
    removed_at = NULL
RETURNING id, provider, installation_id, provider_repo_id, account_login, owner, name, full_name, provider_key, private, default_branch, html_url, archived, last_seen_at, removed_at, created_at, updated_at, (xmax = 0) AS inserted, (SELECT removed_at FROM prev) AS previous_removed_at;

-- name: SoftDeleteForgeRepository :many
UPDATE forge_repositories
SET removed_at = NOW(), updated_at = NOW()
WHERE provider = $1 AND provider_key = $2 AND removed_at IS NULL
RETURNING id, full_name;

-- name: MarkInstallationRepositoriesRemoved :many
UPDATE forge_repositories
SET removed_at = NOW(), updated_at = NOW()
WHERE provider = $1 AND installation_id = $2 AND removed_at IS NULL
RETURNING id, full_name, provider_key;

-- name: SetForgeRepositoryArchived :many
UPDATE forge_repositories
SET archived = $3, updated_at = NOW()
WHERE provider = $1 AND provider_key = $2 AND archived <> $3
RETURNING id, full_name;

-- name: SetForgeRepositoryPrivate :exec
UPDATE forge_repositories
SET private = $3, updated_at = NOW()
WHERE provider = $1 AND provider_key = $2;

-- name: ListForgeRepositoriesByAccount :many
SELECT id, provider, installation_id, provider_repo_id, account_login, owner, name, full_name, provider_key, private, default_branch, html_url, archived, last_seen_at, removed_at, created_at, updated_at
FROM forge_repositories
WHERE provider = $1 AND lower(account_login) = lower($2) AND removed_at IS NULL
ORDER BY full_name ASC;

-- name: GetForgeRepositoryByProviderRepoID :one
SELECT id, provider, installation_id, provider_repo_id, account_login, owner, name, full_name, provider_key, private, default_branch, html_url, archived, last_seen_at, removed_at, created_at, updated_at
FROM forge_repositories
WHERE provider = $1 AND provider_repo_id = $2 AND removed_at IS NULL
ORDER BY updated_at DESC
LIMIT 1;

-- name: GetForgeRepositoryByProviderKey :one
SELECT id, provider, installation_id, provider_repo_id, account_login, owner, name, full_name, provider_key, private, default_branch, html_url, archived, last_seen_at, removed_at, created_at, updated_at
FROM forge_repositories
WHERE provider = $1 AND provider_key = $2 AND removed_at IS NULL
LIMIT 1;
