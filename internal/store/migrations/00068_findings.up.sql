-- +goose Up
-- Findings once per repository, presence per snapshot (ADR-049). A finding
-- is one row of `findings` per (repository, type, fingerprint); a snapshot
-- carries it through one narrow `snapshot_findings` row holding what is
-- true of that occurrence: when it was seen, the rating as scanned, its
-- presence (ADR-034), its reachability, a location or metadata that
-- differ from the finding's latest, and whether the scan stopped matching
-- it there. `vulnerabilities` becomes a view with today's columns, so
-- every reader keeps its query.

CREATE TABLE findings (
    id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id                    uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    type                       vulnerability_type NOT NULL,
    fingerprint                text NOT NULL,
    title                      text NOT NULL DEFAULT '',
    description                text NOT NULL DEFAULT '',
    primary_identifier_kind    text NOT NULL DEFAULT '',
    primary_identifier_value   text NOT NULL DEFAULT '',
    -- The rating as last written by a scan, or the override when one is set.
    severity                   severity_level NOT NULL,
    severity_override_reason   text,
    severity_override_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    cvss_version               cvss_version,
    cvss_vector                text NOT NULL DEFAULT '',
    rated_by                   text NOT NULL DEFAULT '',
    -- A person's decision (ADR-012, ADR-023): suppressed or resolved by
    -- triage, detected when nobody decided; history in
    -- vulnerability_state_transitions. What a producer reported is on the
    -- snapshot row.
    status                     vulnerability_status NOT NULL DEFAULT 'detected',
    state_comment              text,
    resolved_at                timestamptz,
    resolved_by                uuid REFERENCES users(id) ON DELETE SET NULL,
    due_date                   date,
    present_on_default_branch  boolean NOT NULL DEFAULT true,
    resolved_on_default_branch boolean NOT NULL DEFAULT false,
    scanner_name               text NOT NULL DEFAULT '',
    scanner_vendor             text NOT NULL DEFAULT '',
    scanner_version            text NOT NULL DEFAULT '',
    scanner_external_id        text NOT NULL DEFAULT '',
    -- The latest known location; an occurrence elsewhere overrides it on
    -- its snapshot row.
    file_path                  text,
    start_line                 integer,
    end_line                   integer,
    location_hash              text,
    component_id               uuid REFERENCES components(id) ON DELETE SET NULL,
    component_name             text,
    component_version          text,
    component_purl             text,
    ecosystem                  text,
    advisory_id                uuid REFERENCES advisories(id) ON DELETE SET NULL,
    affected_range_id          uuid REFERENCES affected_ranges(id) ON DELETE SET NULL,
    language                   text,
    solution                   text,
    has_remediation            boolean NOT NULL DEFAULT false,
    remediation_link           text,
    secret_type                text,
    secret_hash                text,
    commit_sha                 text,
    author_email               text,
    verified                   boolean,
    created_by                 uuid REFERENCES users(id) ON DELETE SET NULL,
    metadata                   jsonb NOT NULL DEFAULT '{}'::jsonb,
    rule_ref_id                uuid REFERENCES scan_rules(id) ON DELETE SET NULL,
    origin                     finding_origin NOT NULL DEFAULT 'scanner',
    origin_api_key_id          uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    origin_token_name          text NOT NULL DEFAULT '',
    origin_owner_type          text NOT NULL DEFAULT '',
    origin_owner_id            uuid,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    first_seen_at              timestamptz NOT NULL DEFAULT now(),
    last_seen_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repo_id, type, fingerprint),
    CONSTRAINT findings_line_bounds_check CHECK (start_line IS NULL OR start_line > 0),
    CONSTRAINT findings_line_range_check CHECK (end_line IS NULL OR start_line IS NULL OR end_line >= start_line),
    CONSTRAINT findings_manual_created_by CHECK (type <> 'manual' OR created_by IS NOT NULL),
    CONSTRAINT findings_origin_agent_owner CHECK (origin <> 'agent' OR (origin_owner_type <> '' AND origin_owner_id IS NOT NULL)),
    CONSTRAINT findings_origin_human_actor CHECK (origin <> 'human' OR created_by IS NOT NULL),
    CONSTRAINT findings_origin_owner_type CHECK (origin_owner_type IN ('', 'user', 'org'))
);
CREATE INDEX findings_org_status_idx ON findings (org_id, severity, status);
CREATE INDEX findings_repo_idx ON findings (repo_id);
CREATE INDEX findings_fingerprint_idx ON findings (fingerprint);
CREATE INDEX findings_advisory_idx ON findings (advisory_id);
CREATE INDEX findings_component_idx ON findings (component_id);
CREATE INDEX findings_rule_ref_idx ON findings (rule_ref_id);
CREATE INDEX findings_primary_ident_idx ON findings (primary_identifier_value);
CREATE INDEX findings_primary_ident_trgm ON findings USING gin (primary_identifier_value gin_trgm_ops);
CREATE INDEX findings_title_trgm ON findings USING gin (title gin_trgm_ops);
CREATE INDEX findings_origin_idx ON findings (org_id, origin) WHERE origin <> 'scanner';
CREATE INDEX findings_origin_api_key_idx ON findings (origin_api_key_id) WHERE origin_api_key_id IS NOT NULL;

CREATE TABLE snapshot_findings (
    snapshot_id           uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    finding_id            uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    detected_at           timestamptz NOT NULL DEFAULT now(),
    -- As scanned (ADR-049 §6): the rating this snapshot was given, refreshed
    -- where the scan pass re-matches, kept where it does not.
    severity              severity_level NOT NULL,
    cvss_score            numeric(4,2),
    confidence            text,
    reachability          reachability,
    -- The status the producer reported for this occurrence: detected, or
    -- suppressed in source (a #nosec with its justification), or resolved
    -- when a producer says so. The timeline reads the changes between
    -- snapshots.
    scan_status           vulnerability_status NOT NULL DEFAULT 'detected',
    -- The scan stopped matching it on this snapshot: resolved here, while
    -- the finding keeps its triage state.
    resolved_at           timestamptz,
    presence              finding_presence NOT NULL DEFAULT 'reported',
    presence_reason       text,
    last_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    consecutive_absences  integer NOT NULL DEFAULT 0,
    -- Overrides: NULL when equal to the finding's latest.
    file_path             text,
    start_line            integer,
    end_line              integer,
    location_hash         text,
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb,   -- '{}' means the finding's
    PRIMARY KEY (snapshot_id, finding_id),
    CONSTRAINT snapshot_findings_cvss_score_range CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))
);
CREATE INDEX snapshot_findings_finding_idx ON snapshot_findings (finding_id, snapshot_id);
CREATE INDEX snapshot_findings_severity_idx ON snapshot_findings (snapshot_id, severity, detected_at DESC);
CREATE INDEX snapshot_findings_carried_idx ON snapshot_findings (snapshot_id) WHERE presence <> 'reported';

-- The view's derived columns are functions so their types are declared:
-- the query compiler types a function call, not a CASE expression.
-- +goose StatementBegin
CREATE FUNCTION severity_rank_of(s severity_level) RETURNS smallint
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE s
        WHEN 'critical' THEN 6 WHEN 'high' THEN 5 WHEN 'medium' THEN 4
        WHEN 'unknown' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END::smallint
$$;
-- +goose StatementEnd
-- +goose StatementBegin
-- A person's override wins over the rating as scanned.
CREATE FUNCTION finding_effective_severity(override_by uuid, finding_severity severity_level, scanned severity_level) RETURNS severity_level
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN override_by IS NOT NULL THEN finding_severity ELSE scanned END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
-- A person's decision wins; else the scan stopping to match it here; else
-- what the producer reported for this occurrence.
CREATE FUNCTION finding_effective_status(finding_status vulnerability_status, scan_status vulnerability_status, scan_resolved_at timestamptz) RETURNS vulnerability_status
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN finding_status <> 'detected' THEN finding_status
        WHEN scan_resolved_at IS NOT NULL THEN 'resolved'::vulnerability_status
        ELSE scan_status END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
-- The occurrence's metadata when it differs from the finding's.
CREATE FUNCTION finding_effective_metadata(occurrence jsonb, finding jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN occurrence = '{}'::jsonb THEN finding ELSE occurrence END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
-- The commit of the snapshot where the producer last reported a carried
-- finding; '' when none.
CREATE FUNCTION snapshot_commit_sha(snapshot uuid) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT s.commit_sha FROM snapshots s WHERE s.id = snapshot), '')
$$;
-- +goose StatementEnd

-- Backfill: one finding per identity, taking the attributes of the newest
-- reported row and keeping its id, so the history keyed by that row stays
-- attached; one snapshot row per old row.
INSERT INTO findings (
    id, org_id, repo_id, type, fingerprint, title, description, primary_identifier_kind, primary_identifier_value,
    severity, severity_override_reason, severity_override_by, cvss_version, cvss_vector, rated_by,
    status, state_comment, resolved_at, resolved_by, due_date, present_on_default_branch, resolved_on_default_branch,
    scanner_name, scanner_vendor, scanner_version, scanner_external_id,
    file_path, start_line, end_line, location_hash,
    component_id, component_name, component_version, component_purl, ecosystem, advisory_id, affected_range_id,
    language, solution, has_remediation, remediation_link, secret_type, secret_hash, commit_sha, author_email, verified,
    created_by, metadata, rule_ref_id, origin, origin_api_key_id, origin_token_name, origin_owner_type, origin_owner_id,
    created_at, updated_at, first_seen_at, last_seen_at
)
SELECT DISTINCT ON (v.repo_id, v.type, v.fingerprint)
    v.id, v.org_id, v.repo_id, v.type, v.fingerprint, v.title, v.description, v.primary_identifier_kind, v.primary_identifier_value,
    v.severity, v.severity_override_reason, v.severity_override_by, v.cvss_version, v.cvss_vector, v.rated_by,
    -- Only a person's resolution is the finding's state; what a scan
    -- reported (detected, suppressed in source, resolved) stays per
    -- snapshot.
    CASE WHEN v.status = 'resolved' AND v.resolved_by IS NOT NULL THEN v.status ELSE 'detected'::vulnerability_status END,
    v.state_comment,
    CASE WHEN v.status = 'resolved' AND v.resolved_by IS NOT NULL THEN v.resolved_at END,
    v.resolved_by, v.due_date, v.present_on_default_branch, v.resolved_on_default_branch,
    v.scanner_name, v.scanner_vendor, v.scanner_version, v.scanner_external_id,
    v.file_path, v.start_line, v.end_line, v.location_hash,
    v.component_id, v.component_name, v.component_version, v.component_purl, v.ecosystem, v.advisory_id, v.affected_range_id,
    v.language, v.solution, v.has_remediation, v.remediation_link, v.secret_type, v.secret_hash, v.commit_sha, v.author_email, v.verified,
    v.created_by, v.metadata, v.rule_ref_id, v.origin, v.origin_api_key_id, v.origin_token_name, v.origin_owner_type, v.origin_owner_id,
    v.created_at, v.updated_at, v.first_seen_at, v.last_seen_at
FROM vulnerabilities v
ORDER BY v.repo_id, v.type, v.fingerprint, (v.presence = 'reported') DESC, v.updated_at DESC, v.created_at DESC;

UPDATE findings f SET
    first_seen_at = a.first_seen,
    last_seen_at  = a.last_seen
FROM (
    SELECT repo_id, type, fingerprint, min(first_seen_at) AS first_seen, max(last_seen_at) AS last_seen
    FROM vulnerabilities GROUP BY repo_id, type, fingerprint
) a
WHERE a.repo_id = f.repo_id AND a.type = f.type AND a.fingerprint = f.fingerprint;

INSERT INTO snapshot_findings (
    snapshot_id, finding_id, detected_at, severity, cvss_score, confidence, reachability, scan_status, resolved_at,
    presence, presence_reason, last_seen_snapshot_id, consecutive_absences,
    file_path, start_line, end_line, location_hash, metadata
)
SELECT v.snapshot_id, f.id, v.detected_at, v.original_severity, v.cvss_score, v.confidence, v.reachability,
       v.status,
       CASE WHEN v.status = 'resolved' AND v.resolved_by IS NULL THEN COALESCE(v.resolved_at, v.updated_at) END,
       v.presence, v.presence_reason, v.last_seen_snapshot_id, v.consecutive_absences,
       CASE WHEN v.file_path IS DISTINCT FROM f.file_path THEN v.file_path END,
       CASE WHEN v.start_line IS DISTINCT FROM f.start_line THEN v.start_line END,
       CASE WHEN v.end_line IS DISTINCT FROM f.end_line THEN v.end_line END,
       CASE WHEN v.location_hash IS DISTINCT FROM f.location_hash THEN v.location_hash END,
       CASE WHEN v.metadata <> f.metadata THEN v.metadata ELSE '{}'::jsonb END
FROM vulnerabilities v
JOIN findings f ON f.repo_id = v.repo_id AND f.type = v.type AND f.fingerprint = v.fingerprint
ON CONFLICT (snapshot_id, finding_id) DO NOTHING;

-- Re-key the history to the finding; the copies of a finding across
-- snapshots had each their own history, now merged.
ALTER TABLE vulnerability_state_transitions DROP CONSTRAINT vulnerability_state_transitions_vulnerability_id_fkey;
UPDATE vulnerability_state_transitions t SET vulnerability_id = f.id
FROM vulnerabilities v
JOIN findings f ON f.repo_id = v.repo_id AND f.type = v.type AND f.fingerprint = v.fingerprint
WHERE t.vulnerability_id = v.id AND v.id <> f.id;
ALTER TABLE vulnerability_external_issues DROP CONSTRAINT vulnerability_external_issues_vulnerability_id_fkey;
UPDATE vulnerability_external_issues e SET vulnerability_id = f.id
FROM vulnerabilities v
JOIN findings f ON f.repo_id = v.repo_id AND f.type = v.type AND f.fingerprint = v.fingerprint
WHERE e.vulnerability_id = v.id AND v.id <> f.id
  AND NOT EXISTS (
      SELECT 1 FROM vulnerability_external_issues d
      WHERE d.vulnerability_id = f.id AND d.tracker_type = e.tracker_type AND d.external_id = e.external_id
  );
DELETE FROM vulnerability_external_issues e WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.id = e.vulnerability_id);
DELETE FROM vulnerability_state_transitions t WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.id = t.vulnerability_id);

DROP VIEW finding_cwes;
DROP TABLE vulnerabilities CASCADE;
DROP FUNCTION IF EXISTS vulnerabilities_set_tenant();

ALTER TABLE vulnerability_state_transitions
    ADD CONSTRAINT vulnerability_state_transitions_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES findings(id) ON DELETE CASCADE;
ALTER TABLE vulnerability_external_issues
    ADD CONSTRAINT vulnerability_external_issues_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES findings(id) ON DELETE CASCADE;

-- Today's shape over the two tables. `id` is the finding's: stable across
-- snapshots. Effective severity honours a person's override; status is
-- the finding's unless the scan stopped matching it on this snapshot.
CREATE VIEW vulnerabilities AS
SELECT
    f.id,
    f.type,
    sf.snapshot_id,
    f.title,
    f.description,
    sf.severity AS original_severity,
    finding_effective_severity(f.severity_override_by, f.severity, sf.severity) AS severity,
    f.severity_override_reason,
    f.severity_override_by,
    finding_effective_status(f.status, sf.scan_status, sf.resolved_at) AS status,
    f.state_comment,
    sf.detected_at,
    COALESCE(f.resolved_at, sf.resolved_at) AS resolved_at,
    f.resolved_by,
    f.scanner_name,
    f.scanner_vendor,
    f.scanner_version,
    f.scanner_external_id,
    COALESCE(sf.file_path, f.file_path) AS file_path,
    COALESCE(sf.start_line, f.start_line) AS start_line,
    COALESCE(sf.end_line, f.end_line) AS end_line,
    COALESCE(sf.location_hash, f.location_hash) AS location_hash,
    f.fingerprint,
    f.component_id,
    f.component_name,
    f.component_version,
    f.component_purl,
    f.ecosystem,
    f.advisory_id,
    f.affected_range_id,
    f.language,
    sf.confidence,
    f.solution,
    f.has_remediation,
    f.remediation_link,
    sf.reachability,
    f.due_date,
    f.present_on_default_branch,
    f.resolved_on_default_branch,
    f.secret_type,
    f.secret_hash,
    f.commit_sha,
    f.author_email,
    f.verified,
    f.created_by,
    finding_effective_metadata(sf.metadata, f.metadata) AS metadata,
    f.created_at,
    f.updated_at,
    f.first_seen_at,
    f.last_seen_at,
    severity_rank_of(finding_effective_severity(f.severity_override_by, f.severity, sf.severity)) AS severity_rank,
    f.rule_ref_id,
    f.primary_identifier_kind,
    f.primary_identifier_value,
    f.org_id,
    f.repo_id,
    f.origin,
    f.origin_api_key_id,
    f.origin_token_name,
    f.origin_owner_type,
    f.origin_owner_id,
    sf.cvss_score,
    f.cvss_version,
    f.cvss_vector,
    f.rated_by,
    sf.presence,
    sf.presence_reason,
    sf.last_seen_snapshot_id,
    snapshot_commit_sha(sf.last_seen_snapshot_id) AS last_seen_commit,
    sf.consecutive_absences
FROM snapshot_findings sf
JOIN findings f ON f.id = sf.finding_id;

-- finding_cwes (migration 00040) went with the table; it is one row per
-- finding now, which is what its readers join on.
CREATE VIEW finding_cwes AS
    SELECT f.id AS vulnerability_id, rc.cwe_id, 'rule'::text AS source
      FROM findings f
      JOIN scan_rule_cwes rc ON rc.scan_rule_id = f.rule_ref_id
    UNION ALL
    SELECT f.id, ac.cwe_id, 'advisory'::text
      FROM findings f
      JOIN advisory_cwes ac ON ac.advisory_id = f.advisory_id
    UNION ALL
    -- Declarations only count on manual findings: a scanner finding's CWE is
    -- the scanner's claim, not a triager's opinion.
    SELECT f.id, fa.cwe_id, fa.source::text
      FROM findings f
      JOIN finding_cwe_assertions fa ON fa.repo_id = f.repo_id AND fa.fingerprint = f.fingerprint
     WHERE fa.source = 'sarif_result' OR f.type = 'manual'
    UNION ALL
    -- A leaked secret is CWE-798 (Use of Hard-coded Credentials) by
    -- definition; no secret scanner emits a CWE.
    SELECT f.id, 798, 'type'::text
      FROM findings f
     WHERE f.type = 'secret';
