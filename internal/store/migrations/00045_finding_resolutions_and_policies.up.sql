-- ADR-034 §3: a resolved finding has no row in the snapshot that resolved it,
-- so the evidence lives here — "Resolved in e4f5a6b", "No longer reported by
-- gosec 2.29" — for the timeline and the API.
CREATE TABLE finding_resolutions (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref_id uuid NOT NULL REFERENCES refs(id) ON DELETE CASCADE,
    -- The snapshot whose producer runs resolved the finding.
    snapshot_id uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    type text NOT NULL,
    fingerprint text NOT NULL,
    producer text NOT NULL,
    -- fixed, file_removed, no_longer_reported, producer_changed
    reason text NOT NULL CHECK (reason IN ('fixed', 'file_removed', 'no_longer_reported', 'producer_changed')),
    commit_sha text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (snapshot_id, type, fingerprint)
);
CREATE INDEX finding_resolutions_fingerprint_idx ON finding_resolutions (repo_id, fingerprint);

-- ADR-034 §5: how a producer's absent findings are resolved, per org. No row
-- = the default (coverage; explicit for agent:* producers).
CREATE TABLE producer_policies (
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    producer text NOT NULL,
    policy text NOT NULL CHECK (policy IN ('coverage', 'consecutive-absence', 'explicit')),
    threshold integer NOT NULL DEFAULT 3 CHECK (threshold BETWEEN 1 AND 100),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (org_id, producer)
);
