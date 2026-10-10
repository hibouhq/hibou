-- Postgres cannot drop an enum value; rebuild the type. Unknown folds into
-- 'info', which is what unscored advisories were before ADR-038.
UPDATE advisories SET severity = 'info' WHERE severity = 'unknown';
UPDATE vulnerabilities SET severity = 'info' WHERE severity = 'unknown';
UPDATE vulnerabilities SET original_severity = 'info' WHERE original_severity = 'unknown';
UPDATE notifications SET severity = 'info' WHERE severity = 'unknown';
UPDATE advisory_sources SET severity = NULL WHERE severity = 'unknown';

-- The generated rank depends on the column, so it goes and comes back.
ALTER TABLE vulnerabilities DROP COLUMN severity_rank;

ALTER TYPE severity_level RENAME TO severity_level_old;
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
ALTER TABLE advisories ALTER COLUMN severity DROP DEFAULT;
ALTER TABLE advisories ALTER COLUMN severity TYPE severity_level USING severity::text::severity_level;
ALTER TABLE advisories ALTER COLUMN severity SET DEFAULT 'info';
ALTER TABLE vulnerabilities ALTER COLUMN severity TYPE severity_level USING severity::text::severity_level;
ALTER TABLE vulnerabilities ALTER COLUMN original_severity TYPE severity_level USING original_severity::text::severity_level;
ALTER TABLE notifications ALTER COLUMN severity TYPE severity_level USING severity::text::severity_level;
ALTER TABLE advisory_sources ALTER COLUMN severity TYPE severity_level USING severity::text::severity_level;
DROP TYPE severity_level_old;

ALTER TABLE vulnerabilities ADD COLUMN severity_rank smallint GENERATED ALWAYS AS (
CASE severity
    WHEN 'critical'::severity_level THEN 5
    WHEN 'high'::severity_level THEN 4
    WHEN 'medium'::severity_level THEN 3
    WHEN 'low'::severity_level THEN 2
    WHEN 'info'::severity_level THEN 1
    ELSE 0
END) STORED;
CREATE INDEX idx_vulnerabilities_snapshot_sevrank ON vulnerabilities USING btree (snapshot_id, severity_rank DESC, detected_at DESC);
