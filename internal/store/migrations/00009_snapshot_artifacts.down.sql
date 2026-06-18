ALTER TABLE snapshots ADD COLUMN raw_artifact_url TEXT;
ALTER TABLE snapshots ADD COLUMN artifact_key TEXT NOT NULL DEFAULT '';

DROP TABLE snapshot_artifacts;
