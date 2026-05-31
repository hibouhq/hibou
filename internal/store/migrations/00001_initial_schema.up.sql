CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Enums

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
    'failed',
    'active',
    'archived',
    'purged'
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
    'email',
    'discord'
);

CREATE TYPE scan_status AS ENUM ('pending', 'running', 'complete', 'failed', 'cancelled');
CREATE TYPE cvss_version AS ENUM ('v2', 'v3.0', 'v3.1', 'v4.0');
CREATE TYPE malware_type AS ENUM ('typosquat', 'dependency_confusion', 'backdoor', 'cryptominer', 'data_exfiltration', 'other');
CREATE TYPE notification_status AS ENUM ('unread', 'read', 'dismissed');
CREATE TYPE integration_type AS ENUM ('slack', 'teams', 'discord', 'webhook', 'email');

CREATE TYPE vex_status AS ENUM (
    'not_affected',
    'affected',
    'fixed',
    'under_investigation'
);

CREATE TYPE vex_justification AS ENUM (
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist'
);

CREATE TYPE vex_source AS ENUM (
    'manual',
    'imported',
    'propagated',
    'automated'
);

CREATE TYPE secret_status AS ENUM (
    'open',
    'revoked',
    'false_positive',
    'rotating'
);

-- Core tables

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'github',
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT organizations_provider_slug_key UNIQUE (provider, slug)
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
    pr_state TEXT,
    pr_title TEXT NOT NULL DEFAULT '',
    pr_source_branch TEXT NOT NULL DEFAULT '',
    pr_merged_at TIMESTAMPTZ,
    pr_closed_at TIMESTAMPTZ,
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
    artifact_key TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    image_digest TEXT,
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
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (snapshot_id, component_id)
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
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
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
    image_digests TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
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
    client_type TEXT NOT NULL DEFAULT 'external',
    contact_email TEXT,
    contact_name TEXT,
    notification_prefs JSONB NOT NULL DEFAULT '{}'::jsonb,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
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

-- Analysis engine tables

CREATE TABLE advisories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    severity severity_level NOT NULL DEFAULT 'info',
    cvss_score NUMERIC(4,2),
    cvss_version cvss_version,
    cvss_vector TEXT NOT NULL DEFAULT '',
    cwe_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    is_malware BOOLEAN NOT NULL DEFAULT FALSE,
    malware_type malware_type,
    published_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT advisories_cvss_score_check CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))
);

CREATE TABLE advisory_aliases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    alias TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE advisory_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    severity severity_level,
    cvss_score NUMERIC(4,2),
    cvss_version cvss_version,
    cvss_vector TEXT NOT NULL DEFAULT '',
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT advisory_sources_advisory_provider_key UNIQUE (advisory_id, provider),
    CONSTRAINT advisory_sources_cvss_score_check CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))
);

CREATE TABLE affected_ranges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    introduced TEXT NOT NULL DEFAULT '',
    fixed TEXT NOT NULL DEFAULT '',
    last_affected TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE advisory_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    provider TEXT NOT NULL,
    response_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    advisory_count INTEGER NOT NULL DEFAULT 0,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT advisory_cache_package_provider_key UNIQUE (ecosystem, package_name, provider)
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    status scan_status NOT NULL DEFAULT 'pending',
    providers_requested TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    triggered_by TEXT NOT NULL DEFAULT 'system',
    error_message TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    status scan_status NOT NULL DEFAULT 'pending',
    cache_hits INTEGER NOT NULL DEFAULT 0,
    cache_misses INTEGER NOT NULL DEFAULT 0,
    advisories_found INTEGER NOT NULL DEFAULT 0,
    response_time_ms INTEGER,
    db_version TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CONSTRAINT scan_providers_scan_provider_key UNIQUE (scan_id, provider)
);

CREATE TABLE vuln_matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    affected_range_id UUID REFERENCES affected_ranges(id) ON DELETE SET NULL,
    is_affected BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vuln_matches_snapshot_component_advisory_key UNIQUE (snapshot_id, component_id, advisory_id)
);

CREATE TABLE vex_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    component_purl TEXT,
    status vex_status NOT NULL,
    justification vex_justification,
    impact_statement TEXT NOT NULL DEFAULT '',
    action_statement TEXT NOT NULL DEFAULT '',
    source vex_source NOT NULL DEFAULT 'manual',
    source_document_url TEXT NOT NULL DEFAULT '',
    supplier TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vex_justification_required CHECK (
        status != 'not_affected' OR justification IS NOT NULL
    ),
    CONSTRAINT vex_scope_valid CHECK (
        component_purl IS NULL OR repo_id IS NOT NULL
    )
);

COMMENT ON TABLE vex_statements IS 'VEX statements. When repo_id is set, it must belong to org_id. The store layer validates this lineage on writes.';

CREATE TABLE quality_gates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    max_critical INTEGER NOT NULL DEFAULT 0,
    max_high INTEGER NOT NULL DEFAULT 0,
    max_medium INTEGER,
    max_new_findings INTEGER,
    finding_severities TEXT[] NOT NULL DEFAULT ARRAY['critical','high']::TEXT[],
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    severity severity_level,
    status notification_status NOT NULL DEFAULT 'unread',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    integration_type integration_type NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT integrations_org_name_key UNIQUE (org_id, name)
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL DEFAULT 'user',
    actor_display TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_logs IS 'Immutable operational audit trail. Records all user, CI, and system actions for accountability. Rows must never be updated or deleted.';
COMMENT ON COLUMN audit_logs.actor_type IS 'user, api_key, system, webhook';
COMMENT ON COLUMN audit_logs.action IS 'e.g. scan.trigger, vex.create, vex.update, vex.revoke, release.create, release.update, release.delete, client.create, gate.override, integration.create, setting.update';
COMMENT ON COLUMN audit_logs.resource_type IS 'e.g. scan, advisory, vuln_match, release, client, repository, quality_gate, integration, notification_rule';
COMMENT ON COLUMN audit_logs.context IS 'Action-specific metadata: old/new values for updates, provider list for scans, reason for suppressions';

-- Secret scanning tables

CREATE TABLE secret_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity severity_level NOT NULL DEFAULT 'critical',
    status secret_status NOT NULL DEFAULT 'open',
    status_note TEXT NOT NULL DEFAULT '',
    discovery_context TEXT NOT NULL DEFAULT 'full_scan',
    file_path TEXT NOT NULL,
    start_line INTEGER,
    end_line INTEGER,
    secret_type TEXT NOT NULL DEFAULT '',
    secret_hash TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    author_email TEXT NOT NULL DEFAULT '',
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    fingerprint TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT secret_findings_snapshot_dedup_key UNIQUE (snapshot_id, fingerprint)
);

CREATE TABLE secret_finding_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES secret_findings(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_count INTEGER NOT NULL DEFAULT 1,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT secret_finding_sources_finding_tool_key UNIQUE (finding_id, tool)
);

-- License tables

CREATE TABLE license_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    allowed_licenses TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    denied_licenses TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT license_policies_org_name_key UNIQUE (org_id, name)
);

CREATE TABLE license_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES license_policies(id) ON DELETE CASCADE,
    component_purl TEXT NOT NULL,
    license_id TEXT NOT NULL,
    justification TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes

CREATE INDEX idx_org_members_user_id ON org_members (user_id);
CREATE INDEX idx_teams_org_id ON teams (org_id);
CREATE INDEX idx_team_members_user_id ON team_members (user_id);
CREATE INDEX idx_repositories_org_id ON repositories (org_id);
CREATE INDEX idx_repositories_team_id ON repositories (team_id);
CREATE INDEX idx_refs_repo_id ON refs (repo_id);
CREATE INDEX idx_refs_merge_target_ref_id ON refs (merge_target_ref_id);
CREATE INDEX idx_snapshots_ref_id ON snapshots (ref_id);
CREATE INDEX idx_snapshots_commit_sha ON snapshots (commit_sha);
CREATE INDEX idx_snapshots_status_created ON snapshots (status, created_at);
CREATE INDEX idx_snapshots_labels ON snapshots USING GIN (labels);
CREATE INDEX idx_snapshot_components_component_id ON snapshot_components (component_id);
CREATE INDEX idx_findings_snapshot_id ON findings (snapshot_id);
CREATE INDEX idx_findings_snapshot_id_status ON findings (snapshot_id, status);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);
CREATE INDEX idx_findings_labels ON findings USING GIN (labels);
CREATE INDEX idx_snapshot_components_labels ON snapshot_components USING GIN (labels);
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
CREATE INDEX idx_advisory_aliases_advisory_id ON advisory_aliases (advisory_id);
CREATE INDEX idx_affected_ranges_advisory_id ON affected_ranges (advisory_id);
CREATE INDEX idx_affected_ranges_package ON affected_ranges (ecosystem, package_name);
CREATE INDEX idx_advisory_cache_expires ON advisory_cache (expires_at);
CREATE INDEX idx_scans_snapshot_id ON scans (snapshot_id);
CREATE INDEX idx_scans_status ON scans (status);
CREATE INDEX idx_vuln_matches_snapshot_id ON vuln_matches (snapshot_id);
CREATE INDEX idx_vuln_matches_advisory_id ON vuln_matches (advisory_id);
CREATE INDEX idx_vuln_matches_component_id ON vuln_matches (component_id);
CREATE INDEX idx_vex_statements_org_id ON vex_statements (org_id);
CREATE INDEX idx_vex_statements_advisory_id ON vex_statements (advisory_id);
CREATE INDEX idx_vex_statements_repo_id ON vex_statements (repo_id);
CREATE INDEX idx_vex_statements_status ON vex_statements (status);
CREATE INDEX idx_vex_statements_expires ON vex_statements (expires_at) WHERE expires_at IS NOT NULL;
CREATE UNIQUE INDEX idx_vex_statements_scope ON vex_statements (org_id, advisory_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::UUID), COALESCE(component_purl, ''));
CREATE INDEX idx_quality_gates_org_id ON quality_gates (org_id);
CREATE INDEX idx_quality_gates_repo_id ON quality_gates (repo_id);
CREATE INDEX idx_notifications_user_id ON notifications (user_id);
CREATE INDEX idx_notifications_user_status ON notifications (user_id, status);
CREATE INDEX idx_audit_logs_actor ON audit_logs (actor_id);
CREATE INDEX idx_audit_logs_org ON audit_logs (org_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs (resource_type, resource_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
CREATE INDEX idx_audit_logs_created ON audit_logs (created_at);
CREATE INDEX idx_secret_findings_snapshot_id ON secret_findings (snapshot_id);
CREATE INDEX idx_secret_findings_fingerprint ON secret_findings (fingerprint);
CREATE INDEX idx_secret_findings_status ON secret_findings (status);
CREATE INDEX idx_secret_finding_sources_finding_id ON secret_finding_sources (finding_id);
CREATE INDEX idx_secret_finding_sources_tool ON secret_finding_sources (tool);
CREATE INDEX idx_license_policies_org_id ON license_policies (org_id);
CREATE INDEX idx_license_exceptions_policy_id ON license_exceptions (policy_id);

-- Trigram search indexes
CREATE INDEX idx_advisories_canonical_id_trgm ON advisories USING gin (canonical_id gin_trgm_ops);
CREATE INDEX idx_advisories_title_trgm ON advisories USING gin (title gin_trgm_ops);
CREATE INDEX idx_components_name_trgm ON components USING gin (name gin_trgm_ops);
CREATE INDEX idx_components_purl_trgm ON components USING gin (purl gin_trgm_ops);
CREATE INDEX idx_findings_rule_id_trgm ON findings USING gin (rule_id gin_trgm_ops);
CREATE INDEX idx_findings_tool_trgm ON findings USING gin (tool gin_trgm_ops);
CREATE INDEX idx_findings_message_trgm ON findings USING gin (message gin_trgm_ops);
CREATE INDEX idx_clients_name_trgm ON clients USING gin (name gin_trgm_ops);
