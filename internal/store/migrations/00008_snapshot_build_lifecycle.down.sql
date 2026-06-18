DROP INDEX IF EXISTS snapshots_ref_commit_key;

ALTER TABLE snapshots
    DROP COLUMN IF EXISTS build_url,
    DROP COLUMN IF EXISTS run_id,
    DROP COLUMN IF EXISTS run_number,
    DROP COLUMN IF EXISTS pr_number,
    DROP COLUMN IF EXISTS pr_target_branch,
    DROP COLUMN IF EXISTS tag,
    DROP COLUMN IF EXISTS expected_uploads,
    DROP COLUMN IF EXISTS received_uploads;

ALTER TABLE snapshots ADD COLUMN label TEXT;