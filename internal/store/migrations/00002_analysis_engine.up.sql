-- Phase 2: Canonical Advisory Model
-- Replaces the simple vulnerability tables from 00001 with a provider-agnostic,
-- deduplicated advisory model. See ADR-007.

-- Drop the simple Phase 1 vulnerability model (pre-production, no data to preserve)
DROP TABLE IF EXISTS component_vulnerabilities;
DROP TABLE IF EXISTS vulnerabilities;

-- New enums
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'complete', 'failed', 'cancelled');
CREATE TYPE cvss_version AS ENUM ('v2', 'v3.0', 'v3.1', 'v4.0');
CREATE TYPE malware_type AS ENUM ('typosquat', 'dependency_confusion', 'backdoor', 'cryptominer', 'data_exfiltration', 'other');
CREATE TYPE notification_status AS ENUM ('unread', 'read', 'dismissed');
CREATE TYPE integration_type AS ENUM ('slack', 'teams', 'discord', 'webhook', 'email');

-- advisories: one row per real-world vulnerability, canonical deduplication
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

-- advisory_aliases: all known identifiers for an advisory (CVE, GHSA, PYSEC, etc.)
CREATE TABLE advisory_aliases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    alias TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_advisory_aliases_advisory_id ON advisory_aliases(advisory_id);

-- advisory_sources: which providers reported this advisory and their specific data
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

-- affected_ranges: per advisory, per package, version constraints
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

CREATE INDEX idx_affected_ranges_advisory_id ON affected_ranges(advisory_id);
CREATE INDEX idx_affected_ranges_package ON affected_ranges(ecosystem, package_name);

-- advisory_cache: TTL-based cache for provider API query results
-- This is a PERFORMANCE optimization — NOT vulnerability data.
-- When TTL expires, we re-query the provider. No advisory data is lost.
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

CREATE INDEX idx_advisory_cache_expires ON advisory_cache(expires_at);

-- scans: scan job records with provenance
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

CREATE INDEX idx_scans_snapshot_id ON scans(snapshot_id);
CREATE INDEX idx_scans_status ON scans(status);

-- scan_providers: per-provider results within a scan
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

-- vuln_matches: links snapshot components to advisories via version comparison
CREATE TABLE vuln_matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    affected_range_id UUID REFERENCES affected_ranges(id) ON DELETE SET NULL,
    is_affected BOOLEAN NOT NULL DEFAULT TRUE,
    suppressed BOOLEAN NOT NULL DEFAULT FALSE,
    suppressed_reason TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vuln_matches_snapshot_component_advisory_key UNIQUE (snapshot_id, component_id, advisory_id)
);

CREATE INDEX idx_vuln_matches_snapshot_id ON vuln_matches(snapshot_id);
CREATE INDEX idx_vuln_matches_advisory_id ON vuln_matches(advisory_id);
CREATE INDEX idx_vuln_matches_component_id ON vuln_matches(component_id);

-- quality_gates: configurable gate rules per org/repo
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

CREATE INDEX idx_quality_gates_org_id ON quality_gates(org_id);
CREATE INDEX idx_quality_gates_repo_id ON quality_gates(repo_id);

-- notifications: in-app notification records per user
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

CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_user_status ON notifications(user_id, status);

-- integrations: external integration configs per org (Slack, Teams, Discord, webhook, email)
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

-- audit_logs: immutable record of all user/CI/system actions
-- This is the operational audit trail ("who did what when"), distinct from
-- compliance retention ("what was the vulnerability state at date X").
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
COMMENT ON COLUMN audit_logs.action IS 'e.g. scan.trigger, vuln.suppress, vuln.unsuppress, release.create, release.update, release.delete, client.create, gate.override, integration.create, setting.update';
COMMENT ON COLUMN audit_logs.resource_type IS 'e.g. scan, advisory, vuln_match, release, client, repository, quality_gate, integration, notification_rule';
COMMENT ON COLUMN audit_logs.context IS 'Action-specific metadata: old/new values for updates, provider list for scans, reason for suppressions';

CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_org ON audit_logs(org_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
