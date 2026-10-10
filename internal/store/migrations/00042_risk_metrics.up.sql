-- ADR-038: every rating kept, the one in use chosen per finding, EPSS
-- mirrored.

-- ---------------------------------------------------------------------------
-- Ratings (§2). One row per rater and CVSS version a source publishes; a
-- label-only rating (Debian, Ubuntu) has no version. The rows are rebuilt from
-- each source's raw_data by the startup backfill (ratings_version), so nothing
-- is copied here: the old per-source columns held one rating out of several.
-- ---------------------------------------------------------------------------
CREATE TABLE advisory_ratings (
    advisory_source_id uuid NOT NULL REFERENCES advisory_sources(id) ON DELETE CASCADE,
    rater         text NOT NULL,
    cvss_version  cvss_version,
    cvss_vector   text NOT NULL DEFAULT '',
    cvss_score    numeric(4,2),
    -- The rater's own severity word, when it publishes one. It wins over the
    -- band of its score: Red Hat rates impact separately from CVSS.
    label         severity_level,
    CONSTRAINT advisory_ratings_key UNIQUE NULLS NOT DISTINCT (advisory_source_id, rater, cvss_version),
    CONSTRAINT advisory_ratings_score_range CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    CONSTRAINT advisory_ratings_signal CHECK (cvss_vector <> '' OR cvss_score IS NOT NULL OR label IS NOT NULL)
);

ALTER TABLE advisory_sources
    DROP COLUMN severity,
    DROP COLUMN cvss_score,
    DROP COLUMN cvss_version,
    DROP COLUMN cvss_vector,
    -- Which mapping built this source's ratings. The backfill rebuilds every
    -- source below the current version from raw_data, so a mapping fix
    -- reaches stored data without refetching.
    ADD COLUMN ratings_version smallint NOT NULL DEFAULT 0;

-- The advisory's headline (rule 2: NVD first, else the strongest) and who
-- gave it.
-- A new advisory is unknown until its ratings are merged in the same
-- transaction.
ALTER TABLE advisories
    ADD COLUMN rated_by text NOT NULL DEFAULT '',
    ALTER COLUMN severity SET DEFAULT 'unknown';

-- The CVE feed keeps the strongest container's rating; this names the
-- container (CNA short name or CISA-ADP), so the rating can be attributed.
ALTER TABLE cve_records ADD COLUMN cvss_source text NOT NULL DEFAULT '';

-- ---------------------------------------------------------------------------
-- The rating a finding uses (§2, chosen per finding: a distro's own rating
-- for its OS packages). Copied like severity already is, and recomputed when
-- the advisory's ratings change.
-- ---------------------------------------------------------------------------
ALTER TABLE vulnerabilities
    ADD COLUMN cvss_score   numeric(4,2),
    ADD COLUMN cvss_version cvss_version,
    ADD COLUMN cvss_vector  text NOT NULL DEFAULT '',
    ADD COLUMN rated_by     text NOT NULL DEFAULT '',
    ADD CONSTRAINT vulnerabilities_cvss_score_range CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10));

-- Unknown ranks between medium and low (§3).
ALTER TABLE vulnerabilities ALTER COLUMN severity_rank SET EXPRESSION AS (
CASE severity
    WHEN 'critical'::severity_level THEN 6
    WHEN 'high'::severity_level THEN 5
    WHEN 'medium'::severity_level THEN 4
    WHEN 'unknown'::severity_level THEN 3
    WHEN 'low'::severity_level THEN 2
    WHEN 'info'::severity_level THEN 1
    ELSE 0
END);

-- ---------------------------------------------------------------------------
-- EPSS (§4). Replaced wholesale by the daily sync; never copied onto
-- findings, because the scores move daily.
-- ---------------------------------------------------------------------------
CREATE TABLE epss_scores (
    cve_id      text PRIMARY KEY,
    score       numeric(6,5) NOT NULL CHECK (score >= 0 AND score <= 1),
    percentile  numeric(6,5) NOT NULL CHECK (percentile >= 0 AND percentile <= 1)
);

-- One row: what the mirror holds. A score from one model is not comparable
-- with another's, so the model travels with the data.
CREATE TABLE epss_catalog (
    id            boolean PRIMARY KEY DEFAULT TRUE CHECK (id),
    model_version text NOT NULL,
    score_date    date NOT NULL,
    row_count     integer NOT NULL,
    synced_at     timestamptz NOT NULL DEFAULT now()
);
