CREATE TABLE forge_reconciliation (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider text NOT NULL,
    scope text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('inventory', 'refs', 'pull_requests', 'releases', 'builds')),
    repo_id uuid REFERENCES repositories(id) ON DELETE CASCADE,
    state jsonb NOT NULL DEFAULT '{}',
    next_due_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    attempts integer NOT NULL DEFAULT 0,
    claimed_by uuid,
    claim_expires_at timestamptz,
    requested boolean NOT NULL DEFAULT false,
    UNIQUE (provider, scope, kind)
);
CREATE INDEX forge_reconciliation_due_idx ON forge_reconciliation(next_due_at);

CREATE TABLE forge_reconciliation_runs (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES forge_reconciliation(id) ON DELETE CASCADE,
    queued_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz,
    error text NOT NULL DEFAULT ''
);
CREATE INDEX forge_reconciliation_runs_time_idx ON forge_reconciliation_runs(started_at);

CREATE TABLE forge_analysis_observations (
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_name text NOT NULL,
    commit_sha text NOT NULL,
    analysis_revision text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, ref_name, commit_sha, analysis_revision)
);
