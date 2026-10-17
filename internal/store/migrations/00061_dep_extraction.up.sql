-- Built-in dependency inventory (ADR-045 §4.1): a server-side job extracts
-- lockfiles and manifests from the repository at a commit, renders a
-- CycloneDX document and stores it as a snapshot artifact, which the
-- existing artifact processing ingests like an upload. Nothing here runs
-- repository code.

-- One job per push to an eager ref. Same queue shape as secret_scan_jobs:
-- claim with a lease, bounded attempts, coalesced per (repo, ref) while
-- pending so a push burst extracts the newest commit once.
CREATE TABLE dep_extraction_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_name text NOT NULL,
    -- The commit to extract; empty means the ref's head at claim time.
    commit_sha text NOT NULL DEFAULT '',
    -- push | release | enrollment | manual
    reason text NOT NULL DEFAULT 'push',
    snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'complete', 'failed')),
    claimed_by text,
    claim_expires_at timestamp with time zone,
    attempts integer NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT '',
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    started_at timestamp with time zone,
    finished_at timestamp with time zone
);

CREATE UNIQUE INDEX dep_extraction_jobs_pending_key
    ON dep_extraction_jobs (repo_id, ref_name)
    WHERE status = 'pending';

CREATE INDEX dep_extraction_jobs_claim_idx
    ON dep_extraction_jobs (status, claim_expires_at, created_at);

-- One row per extraction, keyed by the snapshot it fed. input_digest is a
-- sha256 over the recognised files' blob ids plus the extractor version:
-- the inventory is a pure function of both, so a later snapshot with the
-- same digest reuses the stored document instead of extracting again
-- (ADR-045 §4.1, digest reuse across branches and tags).
CREATE TABLE dep_extraction_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    snapshot_id uuid NOT NULL UNIQUE REFERENCES snapshots(id) ON DELETE CASCADE,
    commit_sha text NOT NULL,
    input_digest text NOT NULL,
    extractor_version text NOT NULL,
    artifact_id uuid REFERENCES snapshot_artifacts(id) ON DELETE SET NULL,
    object_key text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL DEFAULT 0,
    component_count integer NOT NULL DEFAULT 0,
    -- Modules found, with completeness and reason (ADR-045 §5).
    modules jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Set when the document was reused from an earlier run with the same
    -- digest rather than extracted.
    reused_from uuid REFERENCES dep_extraction_runs(id) ON DELETE SET NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX dep_extraction_runs_digest_idx
    ON dep_extraction_runs (repo_id, input_digest, extractor_version, created_at DESC);
