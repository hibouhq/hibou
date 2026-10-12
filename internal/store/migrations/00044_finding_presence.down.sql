DROP INDEX vulnerabilities_carried_idx;
ALTER TABLE vulnerabilities
    DROP COLUMN consecutive_absences,
    DROP COLUMN last_seen_commit,
    DROP COLUMN last_seen_snapshot_id,
    DROP COLUMN presence_reason,
    DROP COLUMN presence;
DROP TYPE finding_presence;
