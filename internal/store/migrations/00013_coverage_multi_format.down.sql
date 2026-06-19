DELETE FROM coverage_reports cr
USING (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY snapshot_id
               ORDER BY lines_valid DESC, format ASC
           ) AS rn
    FROM coverage_reports
) ranked
WHERE cr.id = ranked.id
  AND ranked.rn > 1;

ALTER TABLE coverage_reports
    DROP CONSTRAINT coverage_reports_snapshot_format_key;

ALTER TABLE coverage_reports
    ADD CONSTRAINT coverage_reports_snapshot_key UNIQUE (snapshot_id);
