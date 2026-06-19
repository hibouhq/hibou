CREATE TABLE snapshot_dependency_roots (
    snapshot_id UUID PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
