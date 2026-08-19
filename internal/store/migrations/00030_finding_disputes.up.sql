-- ADR-026: a dispute is the human-axis override for an in-source suppression.
-- The scanner keeps reporting the finding as suppressed (the directive is in
-- the code); a dispute row says a human contests that call, so the finding
-- stays visible and gating until the directive is removed or the dispute
-- withdrawn. Separate table from finding_acceptances on purpose: an acceptance
-- row means "not gating", a dispute means the opposite — sharing the table
-- would invert that invariant for every consumer (fail-unsafe).
CREATE TABLE finding_disputes (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    reason text NOT NULL,
    disputed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (repo_id, fingerprint)
);

CREATE INDEX finding_disputes_repo_idx ON finding_disputes (repo_id);
