CREATE TABLE remediation_workload_attempts (
    job_id uuid NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
    lease_token uuid NOT NULL,
    attempt text NOT NULL,
    job_uid text NOT NULL,
    pod_uid text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, lease_token, attempt)
);
