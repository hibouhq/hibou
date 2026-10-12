ALTER TABLE producer_runs DROP COLUMN plan_job_id, DROP COLUMN plan_id;
ALTER TABLE snapshot_artifacts DROP COLUMN plan_job_id, DROP COLUMN plan_id;
DROP TABLE scan_plans;
