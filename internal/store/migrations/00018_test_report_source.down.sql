-- Collapse back to one report per snapshot. Keep the earliest source per snapshot
-- to satisfy the restored UNIQUE(snapshot_id); extra per-source rows are dropped.
DELETE FROM test_reports tr
USING test_reports keep
WHERE tr.snapshot_id = keep.snapshot_id
  AND tr.ctid <> keep.ctid
  AND keep.created_at <= tr.created_at;
ALTER TABLE test_reports DROP CONSTRAINT test_reports_snapshot_source_key;
ALTER TABLE test_reports DROP COLUMN source;
ALTER TABLE test_reports ADD CONSTRAINT test_reports_snapshot_key UNIQUE (snapshot_id);
