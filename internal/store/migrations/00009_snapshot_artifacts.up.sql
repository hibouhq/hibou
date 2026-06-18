CREATE TABLE snapshot_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    format TEXT,
    tool_name TEXT,
    object_key TEXT NOT NULL,
    sha256 TEXT,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    content_type TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX snapshot_artifacts_snapshot_id_idx ON snapshot_artifacts (snapshot_id);

ALTER TABLE snapshots DROP COLUMN raw_artifact_url;
ALTER TABLE snapshots DROP COLUMN artifact_key;
