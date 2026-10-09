ALTER TABLE vulnerabilities ADD COLUMN owasp_top_10 text;
ALTER TABLE cve_records ADD COLUMN cwe_ids text[] DEFAULT ARRAY[]::text[] NOT NULL;
ALTER TABLE advisories ADD COLUMN cwe_ids text[] DEFAULT ARRAY[]::text[] NOT NULL;
ALTER TABLE scan_rules ADD COLUMN cwe_ids text[] DEFAULT ARRAY[]::text[] NOT NULL;
CREATE INDEX idx_scan_rules_cwe_ids ON scan_rules USING gin (cwe_ids);

UPDATE scan_rules sr SET cwe_ids = sub.ids
  FROM (SELECT scan_rule_id, array_agg('CWE-' || cwe_id ORDER BY cwe_id) AS ids
          FROM scan_rule_cwes GROUP BY scan_rule_id) sub
 WHERE sub.scan_rule_id = sr.id;
UPDATE advisories a SET cwe_ids = sub.ids
  FROM (SELECT advisory_id, array_agg('CWE-' || cwe_id ORDER BY cwe_id) AS ids
          FROM advisory_cwes GROUP BY advisory_id) sub
 WHERE sub.advisory_id = a.id;
UPDATE cve_records c SET cwe_ids = sub.ids
  FROM (SELECT cve_id, array_agg('CWE-' || cwe_id ORDER BY cwe_id) AS ids
          FROM cve_record_cwes GROUP BY cve_id) sub
 WHERE sub.cve_id = c.cve_id;

DROP VIEW IF EXISTS finding_cwes;
DROP TABLE IF EXISTS finding_cwe_assertions;
DROP TYPE IF EXISTS finding_cwe_source;
DROP TABLE IF EXISTS cve_record_cwes;
DROP TABLE IF EXISTS advisory_cwes;
DROP TABLE IF EXISTS scan_rule_cwes;
