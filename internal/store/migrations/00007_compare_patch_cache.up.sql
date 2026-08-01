-- Cached forge compare results (ADR-019). The forge already computes which
-- lines a change touched; both commit SHAs are immutable, so a cached entry can
-- never go stale and needs no TTL. Rows die with the repository.
--
-- payload holds the serialized changed-line map (path -> added line numbers)
-- plus per-file status, exactly as parsed from the forge's compare response.
CREATE TABLE compare_patch_cache (
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    base_sha text NOT NULL,
    head_sha text NOT NULL,
    -- The forge capped the file list (GitHub compare returns at most 300
    -- files); callers must surface this so a partial number is never shown as
    -- complete.
    truncated boolean DEFAULT false NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (repo_id, base_sha, head_sha)
);
