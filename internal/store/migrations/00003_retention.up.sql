ALTER TYPE snapshot_status ADD VALUE IF NOT EXISTS 'active';
ALTER TYPE snapshot_status ADD VALUE IF NOT EXISTS 'archived';
ALTER TYPE snapshot_status ADD VALUE IF NOT EXISTS 'purged';

ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS artifact_key TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_snapshots_status_created ON snapshots(status, created_at);
