CREATE INDEX dep_extraction_jobs_snapshot_created_idx
    ON dep_extraction_jobs(snapshot_id, created_at DESC, id DESC)
    WHERE snapshot_id IS NOT NULL;
