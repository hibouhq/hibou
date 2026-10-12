-- ADR-035 §4 / ADR-036 §3: a reproducible scan plan, persisted before CI
-- executes it, so a report can be bound to the job that was planned and its
-- declared scope compared with what ran.
CREATE TABLE scan_plans (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_name text NOT NULL,
    commit_sha text NOT NULL,
    base_commit_sha text,
    mode text NOT NULL CHECK (mode IN ('baseline', 'full', 'sweep')),
    digest text NOT NULL,
    detection_revision text NOT NULL,
    catalog_revision text NOT NULL,
    -- The whole scanplan.Plan document (jobs, artifacts, rationale).
    plan jsonb NOT NULL,
    created_by_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX scan_plans_repo_idx ON scan_plans (repo_id, created_at DESC);

-- Which plan job produced an artifact and its runs. NULL for reports that
-- were not planned (externally produced SARIF stays accepted, ADR-035 §1).
ALTER TABLE snapshot_artifacts
    ADD COLUMN plan_id uuid REFERENCES scan_plans(id) ON DELETE SET NULL,
    ADD COLUMN plan_job_id text;
ALTER TABLE producer_runs
    ADD COLUMN plan_id uuid REFERENCES scan_plans(id) ON DELETE SET NULL,
    ADD COLUMN plan_job_id text;
