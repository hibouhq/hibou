DROP INDEX IF EXISTS snapshots_build_identity_key;

ALTER TABLE snapshots
    DROP COLUMN IF EXISTS run_attempt;

CREATE UNIQUE INDEX snapshots_ref_commit_key ON snapshots (ref_id, commit_sha);
