CREATE TABLE forge_org_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider TEXT NOT NULL,
    account TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    granted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX forge_org_admins_identity_key ON forge_org_admins (provider, account, provider_user_id);
CREATE INDEX forge_org_admins_pending_idx ON forge_org_admins (provider, provider_user_id) WHERE granted = false;
CREATE INDEX forge_org_admins_account_idx ON forge_org_admins (provider, account);
