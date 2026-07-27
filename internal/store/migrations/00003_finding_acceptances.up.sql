-- Accept/unaccept for findings, keyed by fingerprint so the decision survives
-- snapshot churn (vulnerability rows are recreated per snapshot). Mirrors the
-- VEX flow for dependency vulns; this covers SAST/secret/etc findings and,
-- later, license violations.
CREATE TABLE finding_acceptances (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    status text NOT NULL CHECK (status IN ('accepted', 'false_positive')),
    reason text NOT NULL,
    accepted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (repo_id, fingerprint)
);

CREATE INDEX finding_acceptances_repo_idx ON finding_acceptances (repo_id);
