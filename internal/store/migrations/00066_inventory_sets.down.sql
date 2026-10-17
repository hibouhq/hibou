-- +goose Down
DROP VIEW snapshot_dependency_roots;
DROP VIEW component_dependencies;
DROP VIEW snapshot_components;

CREATE TABLE snapshot_components (
    snapshot_id  uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (snapshot_id, component_id)
);
CREATE INDEX idx_snapshot_components_component_id ON snapshot_components (component_id);
INSERT INTO snapshot_components (snapshot_id, component_id, labels)
SELECT s.id, c.component_id, c.labels FROM snapshots s JOIN inventory_set_components c ON c.set_id = s.inventory_set_id;

CREATE TABLE component_dependencies (
    id                      uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    snapshot_id             uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id            uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    depends_on_component_id uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    created_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, component_id, depends_on_component_id)
);
CREATE INDEX idx_component_dependencies_snapshot ON component_dependencies (snapshot_id);
INSERT INTO component_dependencies (snapshot_id, component_id, depends_on_component_id)
SELECT s.id, e.component_id, e.depends_on_component_id FROM snapshots s JOIN inventory_set_edges e ON e.set_id = s.inventory_set_id;

CREATE TABLE snapshot_dependency_roots (
    snapshot_id  uuid PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
    component_id uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE
);
INSERT INTO snapshot_dependency_roots (snapshot_id, component_id)
SELECT s.id, st.root_component_id FROM snapshots s JOIN inventory_sets st ON st.id = s.inventory_set_id WHERE st.root_component_id IS NOT NULL;

ALTER TABLE snapshots DROP COLUMN inventory_set_id;
DROP TABLE inventory_sources;
DROP TRIGGER inventory_set_edges_guard ON inventory_set_edges;
DROP TRIGGER inventory_set_components_guard ON inventory_set_components;
DROP TRIGGER inventory_sets_guard ON inventory_sets;
DROP FUNCTION inventory_set_rows_guard();
DROP FUNCTION inventory_sets_guard();
DROP FUNCTION inventory_seal_staged(uuid, uuid, uuid);
DROP FUNCTION inventory_staging_digest(uuid, uuid);
DROP TABLE inventory_staging_edges;
DROP TABLE inventory_staging_components;
SET LOCAL hibou.inventory_gc = 'on';
DROP TABLE inventory_set_edges;
DROP TABLE inventory_set_components;
DROP TABLE inventory_sets;
