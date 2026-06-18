ALTER TABLE snapshots
    ADD COLUMN run_attempt TEXT;

DROP INDEX IF EXISTS snapshots_ref_commit_key;

CREATE UNIQUE INDEX snapshots_build_identity_key ON snapshots (
    ref_id,
    commit_sha,
    COALESCE(run_id, ''),
    COALESCE(run_attempt, '')
);
