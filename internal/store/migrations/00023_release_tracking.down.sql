ALTER TABLE deployments DROP CONSTRAINT deployments_release_id_fkey;
ALTER TABLE deployments
    ADD CONSTRAINT deployments_release_id_fkey FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE;
DROP INDEX IF EXISTS idx_deployments_release_id;
ALTER TABLE releases
    DROP COLUMN IF EXISTS dismissed_commit_sha,
    DROP COLUMN IF EXISTS diverged_at,
    DROP COLUMN IF EXISTS pending_snapshot_id,
    DROP COLUMN IF EXISTS source,
    DROP COLUMN IF EXISTS html_url;
