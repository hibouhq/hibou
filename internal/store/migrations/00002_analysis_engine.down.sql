DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS integrations;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS quality_gates;
DROP TABLE IF EXISTS vuln_matches;
DROP TABLE IF EXISTS scan_providers;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS advisory_cache;
DROP TABLE IF EXISTS affected_ranges;
DROP TABLE IF EXISTS advisory_sources;
DROP TABLE IF EXISTS advisory_aliases;
DROP TABLE IF EXISTS advisories;

DROP TYPE IF EXISTS integration_type;
DROP TYPE IF EXISTS notification_status;
DROP TYPE IF EXISTS malware_type;
DROP TYPE IF EXISTS cvss_version;
DROP TYPE IF EXISTS scan_status;

-- Restore Phase 1 vulnerability tables
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

CREATE INDEX idx_component_vulnerabilities_vulnerability_id ON component_vulnerabilities (vulnerability_id);
