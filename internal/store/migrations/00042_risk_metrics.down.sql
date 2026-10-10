DROP TABLE epss_catalog;
DROP TABLE epss_scores;

ALTER TABLE vulnerabilities ALTER COLUMN severity_rank SET EXPRESSION AS (
CASE severity
    WHEN 'critical'::severity_level THEN 5
    WHEN 'high'::severity_level THEN 4
    WHEN 'medium'::severity_level THEN 3
    WHEN 'low'::severity_level THEN 2
    WHEN 'info'::severity_level THEN 1
    ELSE 0
END);

ALTER TABLE vulnerabilities
    DROP CONSTRAINT vulnerabilities_cvss_score_range,
    DROP COLUMN rated_by,
    DROP COLUMN cvss_vector,
    DROP COLUMN cvss_version,
    DROP COLUMN cvss_score;

ALTER TABLE cve_records DROP COLUMN cvss_source;
ALTER TABLE advisories DROP COLUMN rated_by, ALTER COLUMN severity SET DEFAULT 'info';

ALTER TABLE advisory_sources
    DROP COLUMN ratings_version,
    ADD COLUMN severity severity_level,
    ADD COLUMN cvss_score numeric(4,2),
    ADD COLUMN cvss_version cvss_version,
    ADD COLUMN cvss_vector text NOT NULL DEFAULT '',
    ADD CONSTRAINT advisory_sources_cvss_score_check CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10));

-- Each source gets back its preferred rating (v3 over v4 over v2).
UPDATE advisory_sources s
   SET severity = r.label, cvss_score = r.cvss_score, cvss_version = r.cvss_version, cvss_vector = r.cvss_vector
  FROM (
    SELECT DISTINCT ON (advisory_source_id) advisory_source_id, label, cvss_score, cvss_version, cvss_vector
      FROM advisory_ratings
     ORDER BY advisory_source_id,
              CASE cvss_version WHEN 'v3.1' THEN 4 WHEN 'v3.0' THEN 3 WHEN 'v4.0' THEN 2 WHEN 'v2' THEN 1 ELSE 0 END DESC
  ) r
 WHERE r.advisory_source_id = s.id;
UPDATE advisory_sources SET severity = NULL WHERE severity = 'unknown';

DROP TABLE advisory_ratings;
