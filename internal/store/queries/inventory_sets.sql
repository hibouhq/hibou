-- Inventory sets (ADR-045, Database section): immutable, content-addressed
-- component lists shared by every snapshot with the same inventory. Rows
-- are staged under a key, sealed into a set by inventory_seal_staged (which
-- returns the existing set when the digest is known), and snapshots point
-- at their effective set.

-- Staging rows and edges are written by store.Queries.stageInventory with
-- a multi-array unnest the query compiler does not type-check.

-- name: SealStagedInventory :one
SELECT inventory_seal_staged(sqlc.arg(org_id), sqlc.arg(staging_key), sqlc.narg(root_component_id))::bigint AS set_id;

-- name: DiscardStagedInventoryComponents :exec
DELETE FROM inventory_staging_components WHERE staging_key = $1;

-- name: DiscardStagedInventoryEdges :exec
DELETE FROM inventory_staging_edges WHERE staging_key = $1;

-- name: UpsertInventorySource :one
-- A source re-ingested under the same label (a restored artifact, a
-- re-extraction) replaces its set; a NULL set, artifact or run keeps what
-- is recorded, so a link can be added after the fact.
INSERT INTO inventory_sources (snapshot_id, label, set_id, artifact_id, extraction_run_id)
VALUES (sqlc.arg(snapshot_id), sqlc.arg(label), sqlc.narg(set_id), sqlc.narg(artifact_id), sqlc.narg(extraction_run_id))
ON CONFLICT (snapshot_id, label) DO UPDATE SET
    set_id = COALESCE(EXCLUDED.set_id, inventory_sources.set_id),
    artifact_id = COALESCE(EXCLUDED.artifact_id, inventory_sources.artifact_id),
    extraction_run_id = COALESCE(EXCLUDED.extraction_run_id, inventory_sources.extraction_run_id)
RETURNING id;

-- name: ListInventorySourcesBySnapshot :many
SELECT src.id, src.label, src.set_id, src.artifact_id, src.extraction_run_id, src.created_at,
       (a.id IS NOT NULL AND a.revoked_at IS NOT NULL)::boolean AS revoked
FROM inventory_sources src
LEFT JOIN snapshot_artifacts a ON a.id = src.artifact_id
WHERE src.snapshot_id = $1
ORDER BY src.created_at, src.id;

-- name: StageEffectiveInventoryComponents :exec
-- The merged rows of every active (not revoked) source of the snapshot.
-- Sources from before inventory sets have no set: their rows are the
-- current rows that carry their label, minus the labels of revoked
-- sources.
WITH active AS (
    SELECT src.set_id, src.label
    FROM inventory_sources src
    LEFT JOIN snapshot_artifacts a ON a.id = src.artifact_id
    WHERE src.snapshot_id = sqlc.arg(snapshot_id) AND (a.id IS NULL OR a.revoked_at IS NULL)
), revoked AS (
    SELECT COALESCE(array_agg(src.label), '{}'::text[]) AS labels
    FROM inventory_sources src
    JOIN snapshot_artifacts a ON a.id = src.artifact_id
    WHERE src.snapshot_id = sqlc.arg(snapshot_id) AND a.revoked_at IS NOT NULL
), current_rows AS (
    SELECT c.component_id, c.labels
    FROM snapshots s
    JOIN inventory_set_components c ON c.set_id = s.inventory_set_id
    WHERE s.id = sqlc.arg(snapshot_id)
), source_rows AS (
    SELECT c.component_id, c.labels
    FROM active
    JOIN inventory_set_components c ON c.set_id = active.set_id
    WHERE active.set_id IS NOT NULL
    UNION ALL
    SELECT cr.component_id, cr.labels - (SELECT labels FROM revoked)
    FROM active
    JOIN current_rows cr ON cr.labels ? active.label
    WHERE active.set_id IS NULL
), pairs AS (
    -- Every label value is true (a flat key set), so the keys are enough.
    SELECT r.component_id, k AS label
    FROM source_rows r, jsonb_object_keys(r.labels) AS k
)
INSERT INTO inventory_staging_components (staging_key, component_id, labels)
SELECT sqlc.arg(staging_key), p.component_id, jsonb_object_agg(p.label, true)
FROM pairs p
GROUP BY p.component_id;

-- name: StageEffectiveInventoryEdges :exec
WITH active AS (
    SELECT src.set_id, src.label
    FROM inventory_sources src
    LEFT JOIN snapshot_artifacts a ON a.id = src.artifact_id
    WHERE src.snapshot_id = sqlc.arg(snapshot_id) AND (a.id IS NULL OR a.revoked_at IS NULL)
), current_set AS (
    SELECT s.inventory_set_id AS set_id FROM snapshots s WHERE s.id = sqlc.arg(snapshot_id)
), merged AS (
    SELECT e.component_id, e.depends_on_component_id
    FROM active
    JOIN inventory_set_edges e ON e.set_id = active.set_id
    WHERE active.set_id IS NOT NULL
    UNION
    SELECT e.component_id, e.depends_on_component_id
    FROM active
    CROSS JOIN current_set cs
    JOIN inventory_set_edges e ON e.set_id = cs.set_id
    JOIN inventory_set_components a ON a.set_id = cs.set_id AND a.component_id = e.component_id AND a.labels ? active.label
    JOIN inventory_set_components b ON b.set_id = cs.set_id AND b.component_id = e.depends_on_component_id AND b.labels ? active.label
    WHERE active.set_id IS NULL
)
INSERT INTO inventory_staging_edges (staging_key, component_id, depends_on_component_id)
SELECT sqlc.arg(staging_key), m.component_id, m.depends_on_component_id FROM merged m
ON CONFLICT DO NOTHING;

-- name: GetEffectiveInventoryRoot :one
-- The root of the oldest active source that declares one, else the root
-- the snapshot already has.
SELECT COALESCE(
    (SELECT st.root_component_id
     FROM inventory_sources src
     JOIN inventory_sets st ON st.id = src.set_id
     LEFT JOIN snapshot_artifacts a ON a.id = src.artifact_id
     WHERE src.snapshot_id = sqlc.arg(snapshot_id) AND (a.id IS NULL OR a.revoked_at IS NULL) AND st.root_component_id IS NOT NULL
     ORDER BY src.created_at, src.id
     LIMIT 1),
    (SELECT st.root_component_id FROM snapshots s JOIN inventory_sets st ON st.id = s.inventory_set_id WHERE s.id = sqlc.arg(snapshot_id))
)::uuid AS root_component_id;

-- name: SetSnapshotInventorySet :exec
UPDATE snapshots SET inventory_set_id = sqlc.narg(set_id) WHERE id = sqlc.arg(snapshot_id);

-- name: GetInventorySet :one
SELECT * FROM inventory_sets WHERE id = $1;

-- name: CollectInventorySets :execrows
-- Sets no snapshot and no source references any more (retention purged
-- the snapshots, a source was re-ingested, a staging race lost). Needs
-- SET LOCAL hibou.inventory_gc = 'on' in the transaction.
WITH gc AS (
    SELECT st.id
    FROM inventory_sets st
    WHERE st.created_at < now() - interval '1 hour'
      AND NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.inventory_set_id = st.id)
      AND NOT EXISTS (SELECT 1 FROM inventory_sources src WHERE src.set_id = st.id)
    LIMIT $1
)
DELETE FROM inventory_sets st USING gc WHERE st.id = gc.id;

-- name: InventorySetStats :one
-- Monitoring (ADR-039): sets, their rows, and how many snapshots share
-- them. A reuse ratio near one means something writes non-canonical rows.
SELECT (SELECT count(*) FROM inventory_sets)::bigint AS sets,
       (SELECT count(*) FROM inventory_set_components)::bigint AS component_rows,
       (SELECT count(*) FROM inventory_set_edges)::bigint AS edge_rows,
       (SELECT count(*) FROM snapshots WHERE inventory_set_id IS NOT NULL)::bigint AS snapshots_with_inventory;

-- name: ListInventorySetComponents :many
SELECT component_id, labels FROM inventory_set_components WHERE set_id = $1 ORDER BY component_id;

-- name: ListInventorySetEdges :many
SELECT component_id, depends_on_component_id FROM inventory_set_edges WHERE set_id = $1 ORDER BY component_id, depends_on_component_id;

-- name: StageInventorySourceFromLabel :execrows
-- The rows one source contributed to a snapshot, read back from the
-- effective rows that carry its label with the labels that source writes
-- (its own label and the extractor's provenance keys), never another
-- source's. Used for sources from before inventory sets.
INSERT INTO inventory_staging_components (staging_key, component_id, labels)
SELECT sqlc.arg(staging_key), c.component_id,
       (SELECT COALESCE(jsonb_object_agg(k, true), '{}'::jsonb)
        FROM jsonb_object_keys(c.labels) AS k
        WHERE k = sqlc.arg(label)::text
           OR k LIKE 'relationship:%' OR k LIKE 'scope:%' OR k LIKE 'module:%'
           OR k LIKE 'path:%' OR k LIKE 'resolution:%' OR k LIKE 'registry:%'
           OR k LIKE 'constraint:%' OR k LIKE 'layer:%' OR k LIKE 'base_image:%')
FROM snapshots s
JOIN inventory_set_components c ON c.set_id = s.inventory_set_id
WHERE s.id = sqlc.arg(snapshot_id) AND c.labels ? sqlc.arg(label)::text
ON CONFLICT (staging_key, component_id) DO NOTHING;

-- name: StageInventorySourceEdgesFromLabel :exec
INSERT INTO inventory_staging_edges (staging_key, component_id, depends_on_component_id)
SELECT sqlc.arg(staging_key), e.component_id, e.depends_on_component_id
FROM snapshots s
JOIN inventory_set_edges e ON e.set_id = s.inventory_set_id
JOIN inventory_set_components a ON a.set_id = s.inventory_set_id AND a.component_id = e.component_id AND a.labels ? sqlc.arg(label)::text
JOIN inventory_set_components b ON b.set_id = s.inventory_set_id AND b.component_id = e.depends_on_component_id AND b.labels ? sqlc.arg(label)::text
WHERE s.id = sqlc.arg(snapshot_id)
ON CONFLICT DO NOTHING;
