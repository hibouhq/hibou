ALTER TABLE repositories
    DROP COLUMN retention_artifact_bytes;

ALTER TABLE snapshots
    DROP COLUMN artifact_bytes,
    DROP COLUMN retention_hold,
    DROP COLUMN pinned;
