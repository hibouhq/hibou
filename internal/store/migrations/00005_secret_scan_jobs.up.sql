-- First dedicated queue table (ADR-015 amendment). Snapshot-level claiming does
-- not fit secret scanning: a push may produce no snapshot at all, and one
-- snapshot can need several scans (full plus incremental). Claim semantics are
-- deliberately identical to snapshots.artifact_processing_* so there is one
-- model to reason about.
CREATE TABLE secret_scan_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_name text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('full', 'incremental')),
    from_commit text NOT NULL DEFAULT '',
    to_commit text NOT NULL DEFAULT '',
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

-- Coalesce a push burst: one pending job per (repo, ref, mode), so ten pushes to
-- the same branch collapse into one scan of the newest range instead of ten
-- clones. Enqueue widens the range of the existing row rather than inserting.
CREATE UNIQUE INDEX secret_scan_jobs_pending_key
    ON secret_scan_jobs (repo_id, ref_name, mode)
    WHERE status = 'pending';

-- Claim ordering: oldest pending first, plus reclaim of expired leases.
CREATE INDEX secret_scan_jobs_claimable_idx
    ON secret_scan_jobs (created_at, id)
    WHERE status IN ('pending', 'processing');

CREATE INDEX secret_scan_jobs_repo_idx ON secret_scan_jobs (repo_id, created_at DESC);
