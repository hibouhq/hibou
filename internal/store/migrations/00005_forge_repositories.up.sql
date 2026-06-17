CREATE TABLE forge_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL,
    installation_id BIGINT,
    provider_repo_id TEXT,
    account_login TEXT NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    full_name TEXT NOT NULL,
    provider_key TEXT NOT NULL,
    private BOOLEAN NOT NULL DEFAULT FALSE,
    default_branch TEXT NOT NULL DEFAULT '',
    html_url TEXT NOT NULL DEFAULT '',
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX forge_repositories_provider_key_key ON forge_repositories (provider, provider_key);
CREATE INDEX forge_repositories_provider_account_login_idx ON forge_repositories (provider, account_login);
