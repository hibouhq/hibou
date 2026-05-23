CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE member_role AS ENUM (
    'admin',
    'developer',
    'release_manager',
    'auditor',
    'viewer'
);

CREATE TYPE ref_type AS ENUM (
    'branch',
    'tag',
    'pull_request'
);

CREATE TYPE snapshot_status AS ENUM (
    'pending',
    'processing',
    'complete',
    'failed'
);

CREATE TYPE severity_level AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'info'
);

CREATE TYPE deployment_status AS ENUM (
    'active',
    'rolled_back',
    'superseded'
);

CREATE TYPE notification_destination_type AS ENUM (
    'webhook',
    'slack',
    'teams',
    'email'
);

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_provider_identity_key UNIQUE (provider, provider_id)
);

CREATE TABLE org_members (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role member_role NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT teams_id_org_id_key UNIQUE (id, org_id),
    CONSTRAINT teams_org_slug_key UNIQUE (org_id, slug)
);

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role member_role NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id UUID,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    sync_state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT repositories_team_lineage_fkey
        FOREIGN KEY (team_id, org_id)
        REFERENCES teams(id, org_id)
        ON DELETE SET NULL (team_id),
    CONSTRAINT repositories_org_slug_key UNIQUE (org_id, slug),
    CONSTRAINT repositories_provider_identity_key UNIQUE (org_id, provider, provider_id)
);

CREATE TABLE refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    ref_type ref_type NOT NULL,
    provider_id TEXT,
    merge_target_ref_id UUID,
    latest_commit_sha TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT refs_merge_target_not_self_check CHECK (merge_target_ref_id IS NULL OR merge_target_ref_id <> id),
    CONSTRAINT refs_id_repo_id_key UNIQUE (id, repo_id),
    CONSTRAINT refs_merge_target_repo_lineage_fkey
        FOREIGN KEY (merge_target_ref_id, repo_id)
        REFERENCES refs(id, repo_id)
        ON DELETE SET NULL (merge_target_ref_id),
    CONSTRAINT refs_repo_identity_key UNIQUE (repo_id, name, ref_type)
);

CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ref_id UUID NOT NULL REFERENCES refs(id) ON DELETE CASCADE,
    commit_sha TEXT NOT NULL,
    label TEXT,
    status snapshot_status NOT NULL DEFAULT 'pending',
    raw_artifact_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purl TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    licenses JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT components_purl_version_key UNIQUE (purl, version)
);

CREATE TABLE snapshot_components (
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    PRIMARY KEY (snapshot_id, component_id)
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT,
    aliases TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    severity severity_level NOT NULL,
    cvss_score NUMERIC,
    cvss_vectors JSONB NOT NULL DEFAULT '[]'::jsonb,
    description TEXT NOT NULL DEFAULT '',
    fix_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
    affected_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
    sources JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vulnerabilities_cvss_score_check CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))
);

CREATE UNIQUE INDEX vulnerabilities_cve_id_unique ON vulnerabilities (cve_id) WHERE cve_id IS NOT NULL;

CREATE TABLE component_vulnerabilities (
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    fix_version TEXT,
    source TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (component_id, vulnerability_id)
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity severity_level NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    file_path TEXT NOT NULL,
    start_line INTEGER,
    end_line INTEGER,
    location_hash TEXT NOT NULL,
    message TEXT NOT NULL,
    fingerprint TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT findings_line_bounds_check CHECK (
        start_line IS NULL OR start_line > 0
    ),
    CONSTRAINT findings_line_range_check CHECK (
        end_line IS NULL OR start_line IS NULL OR end_line >= start_line
    ),
    CONSTRAINT findings_snapshot_dedup_key UNIQUE (snapshot_id, tool, rule_id, location_hash)
);

CREATE TABLE releases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_id UUID NOT NULL,
    snapshot_id UUID REFERENCES snapshots(id) ON DELETE SET NULL,
    version TEXT NOT NULL,
    build_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    artifact_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT releases_ref_repo_lineage_fkey
        FOREIGN KEY (ref_id, repo_id)
        REFERENCES refs(id, repo_id)
        ON DELETE RESTRICT,
    CONSTRAINT releases_repo_version_key UNIQUE (repo_id, version)
);

COMMENT ON COLUMN releases.snapshot_id IS 'Invariant: when snapshot_id is set, it must reference a snapshot whose ref belongs to releases.repo_id. PostgreSQL cannot enforce this declaratively because snapshots do not store repo_id directly; the store layer must validate the snapshot -> ref -> repository lineage on writes.';

CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    contact_email TEXT,
    contact_name TEXT,
    notification_prefs JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT clients_org_slug_key UNIQUE (org_id, slug)
);

CREATE TABLE deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    release_id UUID NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    environment TEXT NOT NULL,
    status deployment_status NOT NULL,
    deployed_at TIMESTAMPTZ NOT NULL,
    deployed_by TEXT,
    rollback_target_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE casbin_rules (
    id SERIAL PRIMARY KEY,
    ptype TEXT,
    v0 TEXT,
    v1 TEXT,
    v2 TEXT,
    v3 TEXT,
    v4 TEXT,
    v5 TEXT
);

CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    destination_type notification_destination_type NOT NULL,
    destination_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT notification_rules_org_name_key UNIQUE (org_id, name)
);

CREATE INDEX idx_org_members_user_id ON org_members (user_id);
CREATE INDEX idx_teams_org_id ON teams (org_id);
CREATE INDEX idx_team_members_user_id ON team_members (user_id);
CREATE INDEX idx_repositories_org_id ON repositories (org_id);
CREATE INDEX idx_repositories_team_id ON repositories (team_id);
CREATE INDEX idx_refs_repo_id ON refs (repo_id);
CREATE INDEX idx_refs_merge_target_ref_id ON refs (merge_target_ref_id);
CREATE INDEX idx_snapshots_ref_id ON snapshots (ref_id);
CREATE INDEX idx_snapshots_commit_sha ON snapshots (commit_sha);
CREATE INDEX idx_snapshot_components_component_id ON snapshot_components (component_id);
CREATE INDEX idx_component_vulnerabilities_vulnerability_id ON component_vulnerabilities (vulnerability_id);
CREATE INDEX idx_findings_snapshot_id ON findings (snapshot_id);
CREATE INDEX idx_findings_snapshot_id_status ON findings (snapshot_id, status);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);
CREATE INDEX idx_releases_ref_id ON releases (ref_id);
CREATE INDEX idx_releases_snapshot_id ON releases (snapshot_id);
CREATE INDEX idx_clients_org_id ON clients (org_id);
CREATE INDEX idx_deployments_client_id ON deployments (client_id);
CREATE INDEX idx_deployments_release_id ON deployments (release_id);
CREATE INDEX idx_deployments_rollback_target_id ON deployments (rollback_target_id);
CREATE INDEX idx_api_keys_user_id ON api_keys (user_id);
CREATE UNIQUE INDEX idx_casbin_rules_unique ON casbin_rules (ptype, v0, v1, v2, v3, v4, v5);
CREATE INDEX idx_notification_rules_org_id ON notification_rules (org_id);
CREATE INDEX idx_notification_rules_event_type ON notification_rules (event_type);