ALTER TABLE snapshots DROP COLUMN label;

ALTER TABLE snapshots
    ADD COLUMN build_url TEXT,
    ADD COLUMN run_id TEXT,
    ADD COLUMN run_number TEXT,
    ADD COLUMN pr_number TEXT,
    ADD COLUMN pr_target_branch TEXT,
        ADD COLUMN tag TEXT,
    ADD COLUMN expected_uploads INT,
    ADD COLUMN received_uploads INT NOT NULL DEFAULT 0;

DELETE FROM snapshots s
USING snapshots d
WHERE s.ref_id = d.ref_id
    AND s.commit_sha = d.commit_sha
    AND (
        s.created_at < d.created_at
        OR (s.created_at = d.created_at AND s.id < d.id)
    );

CREATE UNIQUE INDEX snapshots_ref_commit_key ON snapshots (ref_id, commit_sha);
