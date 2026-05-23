DROP INDEX IF EXISTS idx_snapshots_status_created;

ALTER TABLE snapshots DROP COLUMN IF EXISTS artifact_key;
ALTER TABLE snapshots DROP COLUMN IF EXISTS status;
DROP TYPE IF EXISTS snapshot_status;
