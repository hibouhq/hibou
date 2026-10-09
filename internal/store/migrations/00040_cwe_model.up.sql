-- ADR-037: CWE as one normalized, integer-keyed dimension across every
-- finding type. Replaces the three free-text cwe_ids arrays (scan_rules,
-- advisories, cve_records) with claim tables and adds one view that answers
-- "which CWEs does this finding carry". Titles, the View 1000 hierarchy and
-- named sets live in the embedded catalog (internal/cwe), not in tables: a
-- mirrored copy would be rewritten by whichever replica booted last, so a
-- rolling upgrade could silently downgrade it.

-- ---------------------------------------------------------------------------
-- Producer claims. An id the embedded catalog does not know is still the
-- producer's claim: it is shown without a title, never dropped.
-- ---------------------------------------------------------------------------
CREATE TABLE scan_rule_cwes (
    scan_rule_id uuid NOT NULL REFERENCES scan_rules(id) ON DELETE CASCADE,
    cwe_id integer NOT NULL CHECK (cwe_id > 0),
    PRIMARY KEY (scan_rule_id, cwe_id)
);
-- Filters resolve "which rules carry CWE x" once per query (a hashed
-- subplan), so the reverse index covers the answer: index-only, no heap.
CREATE INDEX scan_rule_cwes_cwe_idx ON scan_rule_cwes (cwe_id, scan_rule_id);

CREATE TABLE advisory_cwes (
    advisory_id uuid NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    cwe_id integer NOT NULL CHECK (cwe_id > 0),
    PRIMARY KEY (advisory_id, cwe_id)
);
CREATE INDEX advisory_cwes_cwe_idx ON advisory_cwes (cwe_id, advisory_id);

CREATE TABLE cve_record_cwes (
    cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    cwe_id integer NOT NULL CHECK (cwe_id > 0),
    PRIMARY KEY (cve_id, cwe_id)
);

-- Per-occurrence CWEs, keyed like finding_acceptances so they follow the
-- finding across snapshots instead of living on one snapshot row:
--   sarif_result: SARIF result.taxa, replaced on every ingest of the finding;
--   declared:     the author of a manual finding (a human or an agent token).
CREATE TYPE finding_cwe_source AS ENUM ('sarif_result', 'declared');
CREATE TABLE finding_cwe_assertions (
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    cwe_id integer NOT NULL CHECK (cwe_id > 0),
    source finding_cwe_source NOT NULL,
    declared_by uuid REFERENCES users(id) ON DELETE SET NULL,
    declared_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (repo_id, fingerprint, source, cwe_id),
    -- A SARIF row never names a principal (the producer is the scanner).
    CONSTRAINT finding_cwe_assertions_principal CHECK (
        source = 'declared' OR (declared_by IS NULL AND declared_api_key_id IS NULL))
);
-- Reverse lookup for filters ("which findings assert CWE x"), covering.
CREATE INDEX finding_cwe_assertions_cwe_idx
    ON finding_cwe_assertions (cwe_id, source, repo_id, fingerprint);

-- The definition of "which CWEs does this finding carry". Point reads (a page
-- of findings, a gate delta) select from it by vulnerability_id, which pushes
-- down into each branch as an index lookup. Set-oriented paths compile the
-- same four branches against their own filtered rows instead
-- (filterquery.CWESQL, store.findingCWERowsSQL) — joining a whole snapshot
-- through the view would scan vulnerabilities twice. A store test pins the
-- three to identical results.
CREATE VIEW finding_cwes AS
    SELECT v.id AS vulnerability_id, rc.cwe_id, 'rule'::text AS source
      FROM vulnerabilities v
      JOIN scan_rule_cwes rc ON rc.scan_rule_id = v.rule_ref_id
    UNION ALL
    SELECT v.id, ac.cwe_id, 'advisory'::text
      FROM vulnerabilities v
      JOIN advisory_cwes ac ON ac.advisory_id = v.advisory_id
    UNION ALL
    -- Declarations only count on manual findings: a scanner finding's CWE is
    -- the scanner's claim, not a triager's opinion.
    SELECT v.id, fa.cwe_id, fa.source::text
      FROM vulnerabilities v
      JOIN finding_cwe_assertions fa ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
     WHERE fa.source = 'sarif_result' OR v.type = 'manual'
    UNION ALL
    -- A leaked secret is CWE-798 (Use of Hard-coded Credentials) by
    -- definition; no secret scanner emits a CWE.
    SELECT v.id, 798, 'type'::text
      FROM vulnerabilities v
     WHERE v.type = 'secret';

-- ---------------------------------------------------------------------------
-- Backfill from the arrays through the normalizer's SQL equivalent
-- (internal/cwe.Parse): "CWE-079" → 79; NVD-CWE-Other/noinfo and anything
-- else that does not parse yield a NULL match and are dropped.
-- ---------------------------------------------------------------------------
INSERT INTO scan_rule_cwes (scan_rule_id, cwe_id)
SELECT DISTINCT sr.id, m[1]::integer
  FROM scan_rules sr
 CROSS JOIN LATERAL unnest(sr.cwe_ids) AS raw(value)
 CROSS JOIN LATERAL regexp_match(raw.value, '^\s*(?:external/cwe/)?(?:cwe[-_ ]?)?0*([1-9][0-9]{0,6})\s*$', 'i') AS m
 WHERE m[1] IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO advisory_cwes (advisory_id, cwe_id)
SELECT DISTINCT a.id, m[1]::integer
  FROM advisories a
 CROSS JOIN LATERAL unnest(a.cwe_ids) AS raw(value)
 CROSS JOIN LATERAL regexp_match(raw.value, '^\s*(?:external/cwe/)?(?:cwe[-_ ]?)?0*([1-9][0-9]{0,6})\s*$', 'i') AS m
 WHERE m[1] IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO cve_record_cwes (cve_id, cwe_id)
SELECT DISTINCT c.cve_id, m[1]::integer
  FROM cve_records c
 CROSS JOIN LATERAL unnest(c.cwe_ids) AS raw(value)
 CROSS JOIN LATERAL regexp_match(raw.value, '^\s*(?:external/cwe/)?(?:cwe[-_ ]?)?0*([1-9][0-9]{0,6})\s*$', 'i') AS m
 WHERE m[1] IS NOT NULL
ON CONFLICT DO NOTHING;

DROP INDEX IF EXISTS idx_scan_rules_cwe_ids;
ALTER TABLE scan_rules DROP COLUMN cwe_ids;
ALTER TABLE advisories DROP COLUMN cwe_ids;
ALTER TABLE cve_records DROP COLUMN cwe_ids;
-- Never written by any ingest path; OWASP is now derived from CWE through the
-- owasp-* named sets.
ALTER TABLE vulnerabilities DROP COLUMN owasp_top_10;
