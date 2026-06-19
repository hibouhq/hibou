ALTER TABLE snapshots
    ADD COLUMN artifact_processing_claimed_by TEXT,
    ADD COLUMN artifact_processing_claim_expires_at TIMESTAMPTZ,
    ADD COLUMN artifact_processing_started_at TIMESTAMPTZ,
    ADD COLUMN artifact_processing_finished_at TIMESTAMPTZ,
    ADD COLUMN artifact_processing_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN artifact_processing_last_error TEXT;

CREATE INDEX idx_snapshots_artifact_processing_ready
    ON snapshots (status, artifact_processing_finished_at, artifact_processing_claim_expires_at, created_at, id)
    WHERE status IN ('complete', 'failed');
