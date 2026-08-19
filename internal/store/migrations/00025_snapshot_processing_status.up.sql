-- Snapshots now hold status='processing' between upload finalization and the
-- artifact worker finishing (previously they jumped straight to 'complete',
-- so data views and PR gates read an empty snapshot as the latest complete
-- one). Extend the claim index to cover the new claimable status.
DROP INDEX IF EXISTS idx_snapshots_artifact_processing_ready;
CREATE INDEX idx_snapshots_artifact_processing_ready ON snapshots USING btree (status, artifact_processing_finished_at, artifact_processing_claim_expires_at, created_at, id) WHERE (status = ANY (ARRAY['processing'::snapshot_status, 'complete'::snapshot_status, 'failed'::snapshot_status]));

-- Snapshots already finalized but never processed keep flowing through the
-- worker via the retained 'complete' claim arm; no data backfill needed.
