-- +goose Down
-- The per-snapshot copies this migration merged cannot be told apart
-- again; a faithful rebuild of the old table is a restore from backup.
-- The empty table keeps the schema loadable.
DROP VIEW vulnerabilities;
ALTER TABLE vulnerability_state_transitions DROP CONSTRAINT vulnerability_state_transitions_vulnerability_id_fkey;
ALTER TABLE vulnerability_external_issues DROP CONSTRAINT vulnerability_external_issues_vulnerability_id_fkey;
CREATE TABLE vulnerabilities AS
SELECT f.*, sf.snapshot_id, sf.detected_at, sf.presence, sf.presence_reason, sf.last_seen_snapshot_id, sf.consecutive_absences
FROM snapshot_findings sf JOIN findings f ON f.id = sf.finding_id
WITH NO DATA;
DROP FUNCTION severity_rank_of(severity_level);
DROP FUNCTION finding_effective_severity(uuid, severity_level, severity_level);
DROP FUNCTION finding_effective_status(vulnerability_status, vulnerability_status, timestamptz);
DROP FUNCTION finding_effective_metadata(jsonb, jsonb);
DROP FUNCTION snapshot_commit_sha(uuid);
DROP TABLE snapshot_findings;
DROP TABLE findings;
