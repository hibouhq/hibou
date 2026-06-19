CREATE TABLE component_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    depends_on_component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT component_dependencies_unique UNIQUE (snapshot_id, component_id, depends_on_component_id)
);

CREATE INDEX idx_component_dependencies_snapshot ON component_dependencies (snapshot_id);
