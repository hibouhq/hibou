ALTER TABLE coverage_reports
    DROP CONSTRAINT coverage_reports_snapshot_key;

ALTER TABLE coverage_reports
    ADD CONSTRAINT coverage_reports_snapshot_format_key UNIQUE (snapshot_id, format);
