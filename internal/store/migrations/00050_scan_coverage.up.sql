-- ADR-035 §6: a persisted projection of repository × scanner coverage, so the
-- org matrix reads one table instead of recomputing (or calling the forge)
-- per page. Recomputed when runs, plans, settings or requirements change.
CREATE TABLE scan_coverage (
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scanner_id text NOT NULL,
    state text NOT NULL,
    reason text NOT NULL DEFAULT '',
    configured text NOT NULL,
    required boolean NOT NULL DEFAULT false,
    enforcement text NOT NULL DEFAULT '',
    last_run_at timestamp with time zone,
    last_commit text NOT NULL DEFAULT '',
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (repo_id, scanner_id)
);
CREATE INDEX scan_coverage_state_idx ON scan_coverage (state);
