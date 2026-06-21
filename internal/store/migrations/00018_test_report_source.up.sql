-- Allow multiple test reports per snapshot, one per upload source (e.g. a Go
-- junit-go.xml and a frontend junit-front.xml in the same CI run). Previously a
-- single UNIQUE(snapshot_id) meant the second junit upload overwrote the first,
-- so only one language's tests survived. Reports are now keyed by (snapshot_id,
-- source) and aggregated on read.
ALTER TABLE test_reports DROP CONSTRAINT test_reports_snapshot_key;
ALTER TABLE test_reports ADD COLUMN source TEXT NOT NULL DEFAULT '';
ALTER TABLE test_reports ADD CONSTRAINT test_reports_snapshot_source_key UNIQUE (snapshot_id, source);
