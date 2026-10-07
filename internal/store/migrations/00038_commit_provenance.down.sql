ALTER TABLE pr_checks DROP COLUMN IF EXISTS claims_base_sha;
ALTER TABLE snapshots
    DROP COLUMN IF EXISTS merge_commit_sha,
    DROP COLUMN IF EXISTS base_commit_sha;
-- The purged resolved-fingerprint rows were corrupt; nothing to restore.
