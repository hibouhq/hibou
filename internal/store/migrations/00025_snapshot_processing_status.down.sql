DROP INDEX IF EXISTS idx_snapshots_artifact_processing_ready;
CREATE INDEX idx_snapshots_artifact_processing_ready ON snapshots USING btree (status, artifact_processing_finished_at, artifact_processing_claim_expires_at, created_at, id) WHERE (status = ANY (ARRAY['complete'::snapshot_status, 'failed'::snapshot_status]));

-- Revert stranded in-flight rows so the old claim query still sees them.
UPDATE snapshots SET status = 'complete' WHERE status = 'processing';
