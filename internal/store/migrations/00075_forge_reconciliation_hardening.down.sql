DROP INDEX forge_reconciliation_runs_job_time_idx;
DROP TABLE forge_repository_bindings;
ALTER TABLE forge_repositories DROP COLUMN account_id;
