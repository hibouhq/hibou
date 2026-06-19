DROP INDEX IF EXISTS idx_snapshots_artifact_processing_ready;

ALTER TABLE snapshots
    DROP COLUMN artifact_processing_last_error,
    DROP COLUMN artifact_processing_attempts,
    DROP COLUMN artifact_processing_finished_at,
    DROP COLUMN artifact_processing_started_at,
    DROP COLUMN artifact_processing_claim_expires_at,
    DROP COLUMN artifact_processing_claimed_by;