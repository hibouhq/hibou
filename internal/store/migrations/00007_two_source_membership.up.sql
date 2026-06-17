ALTER TABLE org_members
    ADD COLUMN source TEXT NOT NULL DEFAULT 'invite',
    ADD COLUMN synced_at TIMESTAMPTZ,
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD CONSTRAINT org_members_source_check CHECK (source IN ('forge', 'invite'));

CREATE INDEX org_members_org_id_source_idx ON org_members (org_id, source);

CREATE TABLE user_repo_access (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    role member_role NOT NULL,
    source TEXT NOT NULL DEFAULT 'forge',
    synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, repo_id),
    CONSTRAINT user_repo_access_source_check CHECK (source IN ('forge', 'invite'))
);

CREATE INDEX user_repo_access_repo_id_idx ON user_repo_access (repo_id);
CREATE INDEX user_repo_access_user_id_source_idx ON user_repo_access (user_id, source);