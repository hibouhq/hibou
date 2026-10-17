-- +goose Up
-- Inventory sets (ADR-045, Database section, option B): an inventory is an
-- immutable list of components stored once per organisation, keyed by the
-- digest of its content, and snapshots point at it. A push that changes no
-- dependency costs one pointer instead of a copy of every row; identical
-- inventories across branches, pull requests and reuse by input digest are
-- one set. The three per-snapshot tables become views over the sets so the
-- existing queries keep their shape.

CREATE TABLE inventory_sets (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- sha256 of the canonical rows, edges and root (inventory_staging_digest).
    digest            bytea NOT NULL,
    root_component_id uuid REFERENCES components(id),
    -- Header counts computed by SQL from the set's own rows when it is
    -- sealed, immutable afterwards.
    total_count       integer,
    direct_count      integer,
    indirect_count    integer,
    sealed_at         timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, digest)
);

CREATE TABLE inventory_set_components (
    set_id       bigint NOT NULL REFERENCES inventory_sets(id) ON DELETE CASCADE,
    component_id uuid NOT NULL REFERENCES components(id),
    -- The flat provenance label set ("sbom:<file>", "relationship:direct",
    -- "scope:dev", "module:web", "layer:2"...), as before.
    labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (set_id, component_id)
);
-- "Where is component X used?": component to sets, then sets to snapshots.
CREATE INDEX inventory_set_components_component_idx ON inventory_set_components (component_id, set_id);

CREATE TABLE inventory_set_edges (
    set_id                  bigint NOT NULL REFERENCES inventory_sets(id) ON DELETE CASCADE,
    component_id            uuid NOT NULL REFERENCES components(id),
    depends_on_component_id uuid NOT NULL REFERENCES components(id),
    PRIMARY KEY (set_id, component_id, depends_on_component_id)
);

-- One row per piece of evidence a snapshot has: an uploaded SBOM, the
-- built-in extraction, a recorded deliverable. The set is shared by every
-- source with the same content. set_id is NULL for sources that predate
-- this migration, whose rows are known through their label only.
CREATE TABLE inventory_sources (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    snapshot_id       uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    set_id            bigint REFERENCES inventory_sets(id),
    -- The provenance key the source's rows carry ("sbom:<filename>").
    label             text NOT NULL,
    artifact_id       uuid REFERENCES snapshot_artifacts(id) ON DELETE CASCADE,
    extraction_run_id uuid REFERENCES dep_extraction_runs(id) ON DELETE CASCADE,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, label)
);
CREATE INDEX inventory_sources_set_idx ON inventory_sources (set_id);

-- The merged inventory of a snapshot (ADR-045 §5).
ALTER TABLE snapshots ADD COLUMN inventory_set_id bigint REFERENCES inventory_sets(id);
CREATE INDEX snapshots_inventory_set_idx ON snapshots (inventory_set_id) WHERE inventory_set_id IS NOT NULL;

-- Staging: rows are written here under a per-ingestion key, digested, and
-- copied into a set only when the digest is new. Unlogged: a crash loses
-- nothing that cannot be re-ingested.
CREATE UNLOGGED TABLE inventory_staging_components (
    staging_key  uuid NOT NULL,
    component_id uuid NOT NULL,
    labels       jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (staging_key, component_id)
);
CREATE UNLOGGED TABLE inventory_staging_edges (
    staging_key             uuid NOT NULL,
    component_id            uuid NOT NULL,
    depends_on_component_id uuid NOT NULL,
    PRIMARY KEY (staging_key, component_id, depends_on_component_id)
);

-- +goose StatementBegin
CREATE FUNCTION inventory_staging_digest(p_key uuid, p_root uuid) RETURNS bytea
LANGUAGE sql STABLE AS $$
    SELECT sha256(convert_to(
        COALESCE((SELECT string_agg(c.component_id::text || ' ' || c.labels::text, E'\n' ORDER BY c.component_id)
                  FROM inventory_staging_components c WHERE c.staging_key = p_key), '')
        || E'\n--edges--\n'
        || COALESCE((SELECT string_agg(e.component_id::text || '>' || e.depends_on_component_id::text, E'\n' ORDER BY e.component_id, e.depends_on_component_id)
                     FROM inventory_staging_edges e WHERE e.staging_key = p_key), '')
        || E'\n--root--\n' || COALESCE(p_root::text, ''),
        'UTF8'))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Seals the staged rows as a set of the organisation: an existing set with
-- the same digest is returned and the staged rows are discarded; otherwise
-- the rows are copied, the counts computed from them, and the set sealed.
-- The staging rows are deleted either way.
CREATE FUNCTION inventory_seal_staged(p_org uuid, p_key uuid, p_root uuid) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    d   bytea;
    sid bigint;
BEGIN
    d := inventory_staging_digest(p_key, p_root);
    INSERT INTO inventory_sets (org_id, digest, root_component_id)
    VALUES (p_org, d, p_root)
    ON CONFLICT (org_id, digest) DO NOTHING
    RETURNING id INTO sid;
    IF sid IS NULL THEN
        SELECT id INTO sid FROM inventory_sets WHERE org_id = p_org AND digest = d;
    ELSE
        INSERT INTO inventory_set_components (set_id, component_id, labels)
        SELECT sid, component_id, labels FROM inventory_staging_components WHERE staging_key = p_key;
        INSERT INTO inventory_set_edges (set_id, component_id, depends_on_component_id)
        SELECT sid, component_id, depends_on_component_id FROM inventory_staging_edges WHERE staging_key = p_key;
        UPDATE inventory_sets SET
            total_count    = (SELECT count(*) FROM inventory_set_components WHERE set_id = sid),
            direct_count   = (SELECT count(*) FROM inventory_set_components WHERE set_id = sid AND labels ? 'relationship:direct'),
            indirect_count = (SELECT count(*) FROM inventory_set_components WHERE set_id = sid AND labels ? 'relationship:indirect' AND NOT labels ? 'relationship:direct'),
            sealed_at      = now()
        WHERE id = sid;
    END IF;
    DELETE FROM inventory_staging_components WHERE staging_key = p_key;
    DELETE FROM inventory_staging_edges WHERE staging_key = p_key;
    RETURN sid;
END
$$;
-- +goose StatementEnd

-- Immutability is enforced in the database (ADR-045 §5.3): rows of a sealed
-- set never change; sets are deleted by the garbage collector
-- (SET LOCAL hibou.inventory_gc = 'on') or go with their organisation.
-- +goose StatementBegin
CREATE FUNCTION inventory_sets_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.sealed_at IS NOT NULL THEN
            RAISE EXCEPTION 'inventory set % is sealed and immutable', OLD.id USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF current_setting('hibou.inventory_gc', true) = 'on' OR OLD.sealed_at IS NULL THEN
        RETURN OLD;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = OLD.org_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'inventory set % is deleted by the garbage collector only', OLD.id USING ERRCODE = 'integrity_constraint_violation';
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION inventory_set_rows_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'rows of inventory set % are immutable', OLD.set_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF current_setting('hibou.inventory_gc', true) = 'on' THEN
        RETURN OLD;
    END IF;
    -- The cascade of a set that is gone, or the rows of a set still being
    -- written, may go; the rows of a sealed set may not.
    IF EXISTS (SELECT 1 FROM inventory_sets WHERE id = OLD.set_id AND sealed_at IS NOT NULL) THEN
        RAISE EXCEPTION 'rows of inventory set % are deleted with the set only', OLD.set_id USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN OLD;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER inventory_sets_guard BEFORE UPDATE OR DELETE ON inventory_sets
    FOR EACH ROW EXECUTE FUNCTION inventory_sets_guard();
CREATE TRIGGER inventory_set_components_guard BEFORE UPDATE OR DELETE ON inventory_set_components
    FOR EACH ROW EXECUTE FUNCTION inventory_set_rows_guard();
CREATE TRIGGER inventory_set_edges_guard BEFORE UPDATE OR DELETE ON inventory_set_edges
    FOR EACH ROW EXECUTE FUNCTION inventory_set_rows_guard();

-- Backfill: one effective set per snapshot that has rows, deduplicated by
-- digest within the organisation; one source row per SBOM artifact and
-- per extraction run, known through their label (set_id NULL).
-- +goose StatementBegin
DO $$
DECLARE
    snap RECORD;
    root uuid;
    sid  bigint;
BEGIN
    FOR snap IN
        SELECT s.id, s.org_id FROM snapshots s
        WHERE EXISTS (SELECT 1 FROM snapshot_components sc WHERE sc.snapshot_id = s.id)
    LOOP
        INSERT INTO inventory_staging_components (staging_key, component_id, labels)
        SELECT snap.id, sc.component_id, sc.labels FROM snapshot_components sc WHERE sc.snapshot_id = snap.id;
        INSERT INTO inventory_staging_edges (staging_key, component_id, depends_on_component_id)
        SELECT DISTINCT snap.id, cd.component_id, cd.depends_on_component_id FROM component_dependencies cd WHERE cd.snapshot_id = snap.id;
        SELECT r.component_id INTO root FROM snapshot_dependency_roots r WHERE r.snapshot_id = snap.id;
        sid := inventory_seal_staged(snap.org_id, snap.id, root);
        UPDATE snapshots SET inventory_set_id = sid WHERE id = snap.id;
        INSERT INTO inventory_sources (snapshot_id, label, artifact_id)
        SELECT snap.id, 'sbom:' || a.filename, a.id
        FROM snapshot_artifacts a
        WHERE a.snapshot_id = snap.id AND a.kind = 'sbom' AND a.filename <> ''
        ON CONFLICT (snapshot_id, label) DO NOTHING;
        INSERT INTO inventory_sources (snapshot_id, label, extraction_run_id)
        SELECT snap.id, 'sbom:hibou-depinventory.cdx.json', r.id
        FROM dep_extraction_runs r
        WHERE r.snapshot_id = snap.id
        ON CONFLICT (snapshot_id, label) DO NOTHING;
    END LOOP;
END
$$;
-- +goose StatementEnd

DROP TABLE snapshot_components;
DROP TABLE component_dependencies;
DROP TABLE snapshot_dependency_roots;

-- The per-snapshot shape every reader expects, over the sets.
CREATE VIEW snapshot_components AS
    SELECT s.id AS snapshot_id, c.component_id, c.labels
    FROM snapshots s
    JOIN inventory_set_components c ON c.set_id = s.inventory_set_id;

CREATE VIEW component_dependencies AS
    SELECT s.id AS snapshot_id, e.component_id, e.depends_on_component_id
    FROM snapshots s
    JOIN inventory_set_edges e ON e.set_id = s.inventory_set_id;

CREATE VIEW snapshot_dependency_roots AS
    SELECT s.id AS snapshot_id, st.root_component_id AS component_id
    FROM snapshots s
    JOIN inventory_sets st ON st.id = s.inventory_set_id
    WHERE st.root_component_id IS NOT NULL;
