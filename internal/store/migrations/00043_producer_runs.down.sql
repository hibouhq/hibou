DROP TABLE producer_runs;
DROP TYPE producer_run_outcome;
DROP TYPE producer_run_scope;

ALTER TABLE snapshot_artifacts
    DROP COLUMN config_digest,
    DROP COLUMN tool_version,
    DROP COLUMN scope_paths,
    DROP COLUMN scope;
