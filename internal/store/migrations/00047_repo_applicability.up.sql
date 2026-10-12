-- ADR-035 §3: which catalog scanners apply to a repository at a commit,
-- detected from its tracked paths. Kept per (commit, detection revision) so a
-- plan can cite the exact detection it used, and a recipe change re-detects.
CREATE TABLE repo_applicability (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_name text NOT NULL,
    commit_sha text NOT NULL,
    detection_revision text NOT NULL,
    catalog_revision text NOT NULL,
    -- complete | truncated | unknown
    status text NOT NULL,
    result jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (repo_id, commit_sha, detection_revision, catalog_revision)
);
CREATE INDEX repo_applicability_latest_idx ON repo_applicability (repo_id, created_at DESC);
