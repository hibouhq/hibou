CREATE TYPE vulnerability_type AS ENUM (
    'dependency',
    'sast',
    'secret',
    'malware',
    'dast',
    'container',
    'fuzzing',
    'manual',
    'generic'
);

CREATE TYPE vulnerability_status AS ENUM (
    'detected',
    'confirmed',
    'dismissed',
    'resolved'
);

CREATE TYPE dismissal_reason AS ENUM (
    'acceptable_risk',
    'false_positive',
    'mitigating_control',
    'not_applicable',
    'used_in_tests'
);

CREATE TYPE reachability AS ENUM (
    'reachable',
    'not_reachable',
    'unknown'
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type vulnerability_type NOT NULL,
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    primary_identifier JSONB NOT NULL DEFAULT '{}'::jsonb,
    identifiers JSONB NOT NULL DEFAULT '[]'::jsonb,
    original_severity severity_level NOT NULL,
    severity severity_level NOT NULL,
    severity_override_reason TEXT,
    severity_override_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status vulnerability_status NOT NULL DEFAULT 'detected',
    dismissal_reason dismissal_reason,
    state_comment TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,
    confirmed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    dismissed_at TIMESTAMPTZ,
    dismissed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    scanner_name TEXT NOT NULL DEFAULT '',
    scanner_vendor TEXT NOT NULL DEFAULT '',
    scanner_version TEXT NOT NULL DEFAULT '',
    scanner_external_id TEXT NOT NULL DEFAULT '',
    file_path TEXT,
    start_line INTEGER,
    end_line INTEGER,
    location_hash TEXT,
    fingerprint TEXT NOT NULL,
    component_id UUID REFERENCES components(id) ON DELETE SET NULL,
    component_name TEXT,
    component_version TEXT,
    component_purl TEXT,
    ecosystem TEXT,
    advisory_id UUID REFERENCES advisories(id) ON DELETE SET NULL,
    affected_range_id UUID REFERENCES affected_ranges(id) ON DELETE SET NULL,
    language TEXT,
    confidence TEXT,
    solution TEXT,
    has_remediation BOOLEAN NOT NULL DEFAULT FALSE,
    remediation_link TEXT,
    reachability reachability,
    owasp_top_10 TEXT,
    due_date DATE,
    present_on_default_branch BOOLEAN NOT NULL DEFAULT TRUE,
    resolved_on_default_branch BOOLEAN NOT NULL DEFAULT FALSE,
    secret_type TEXT,
    secret_hash TEXT,
    commit_sha TEXT,
    author_email TEXT,
    verified BOOLEAN,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vulnerabilities_line_bounds_check CHECK (start_line IS NULL OR start_line > 0),
    CONSTRAINT vulnerabilities_line_range_check CHECK (end_line IS NULL OR start_line IS NULL OR end_line >= start_line),
    CONSTRAINT vulnerabilities_manual_created_by CHECK (type != 'manual' OR created_by IS NOT NULL),
    CONSTRAINT vulnerabilities_snapshot_dedup_key UNIQUE (snapshot_id, type, fingerprint)
);

CREATE TABLE vulnerability_state_transitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    state vulnerability_status NOT NULL,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    comment TEXT NOT NULL DEFAULT ''
);

CREATE TABLE vulnerability_external_issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    tracker_type TEXT NOT NULL,
    external_id TEXT NOT NULL,
    url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vuln_ext_issues_dedup UNIQUE (vulnerability_id, tracker_type, external_id)
);

CREATE INDEX idx_vulnerabilities_snapshot_id ON vulnerabilities (snapshot_id);
CREATE INDEX idx_vulnerabilities_snapshot_type ON vulnerabilities (snapshot_id, type);
CREATE INDEX idx_vulnerabilities_type_status ON vulnerabilities (type, status);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities (severity);
CREATE INDEX idx_vulnerabilities_status ON vulnerabilities (status);
CREATE INDEX idx_vulnerabilities_advisory_id ON vulnerabilities (advisory_id);
CREATE INDEX idx_vulnerabilities_component_id ON vulnerabilities (component_id);
CREATE INDEX idx_vulnerabilities_fingerprint ON vulnerabilities (fingerprint);
CREATE INDEX idx_vulnerabilities_detected_at ON vulnerabilities (detected_at DESC);
CREATE INDEX idx_vulnerabilities_type_priority ON vulnerabilities (
    snapshot_id,
    (CASE WHEN type IN ('malware', 'secret') THEN 0 ELSE 1 END),
    detected_at DESC
);
CREATE INDEX idx_vuln_state_transitions_vuln_id ON vulnerability_state_transitions (vulnerability_id);
CREATE INDEX idx_vuln_external_issues_vuln_id ON vulnerability_external_issues (vulnerability_id);
CREATE INDEX idx_vulnerabilities_title_trgm ON vulnerabilities USING gin (title gin_trgm_ops);
CREATE INDEX idx_vulnerabilities_description_trgm ON vulnerabilities USING gin (description gin_trgm_ops);

DROP TABLE IF EXISTS secret_finding_sources CASCADE;
DROP TABLE IF EXISTS secret_findings CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS vuln_matches CASCADE;
DROP TYPE IF EXISTS secret_status;
