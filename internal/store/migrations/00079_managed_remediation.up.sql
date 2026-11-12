CREATE TABLE remediation_jobs (
    id uuid PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    creator_id uuid REFERENCES users(id) ON DELETE SET NULL,
    base_sha text NOT NULL,
    source_ref text NOT NULL,
    target_branch text NOT NULL DEFAULT '',
    revision integer NOT NULL DEFAULT 1,
    state text NOT NULL CHECK (state IN ('queued_prepare','preparing','awaiting_selection','queued_generate','generating','ready','failed','cancelled','expired')),
    request jsonb NOT NULL,
    result jsonb NOT NULL DEFAULT '{}',
    error text NOT NULL DEFAULT '',
    artifact_key text NOT NULL DEFAULT '',
    lease_token uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_jobs_queue ON remediation_jobs(state, created_at);
CREATE INDEX remediation_jobs_repo ON remediation_jobs(repo_id, created_at DESC);
CREATE TABLE remediation_controllers (
    id uuid PRIMARY KEY,
    profile text NOT NULL,
    heartbeat_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE remediation_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
    action text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
