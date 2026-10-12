-- ADR-034 §4 (D5): manual and agent-filed findings ("assertions") have no
-- producer that re-checks them, so they persist until a decision ends them.
-- Their lifecycle is keyed by fingerprint, like finding_acceptances: the
-- vulnerabilities rows are per snapshot and copied forward every commit.
CREATE TABLE finding_assertions (
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    -- Re-assert: a person or an agent confirmed the finding is still there.
    last_confirmed_at timestamp with time zone,
    last_confirmed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    last_confirmed_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    -- Resolve (the problem is gone, triage:write) or retract (the assertion
    -- was wrong, the filing principal), with the reason and the principal.
    closed_kind text CHECK (closed_kind IN ('resolved', 'retracted')),
    closed_at timestamp with time zone,
    closed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    closed_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    closed_reason text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (repo_id, fingerprint),
    CONSTRAINT finding_assertions_closed_together CHECK ((closed_kind IS NULL) = (closed_at IS NULL))
);
