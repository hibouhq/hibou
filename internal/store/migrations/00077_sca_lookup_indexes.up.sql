CREATE INDEX dep_extraction_jobs_repo_ref_created_idx
    ON dep_extraction_jobs(repo_id, ref_name, created_at DESC, id DESC);
CREATE INDEX scans_snapshot_created_idx ON scans(snapshot_id, created_at DESC, id DESC);
