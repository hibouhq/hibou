-- name: UpsertComponent :one
INSERT INTO components (purl, name, version, ecosystem, licenses)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (purl, version) DO UPDATE SET
	name = EXCLUDED.name,
	ecosystem = EXCLUDED.ecosystem,
	licenses = CASE WHEN cardinality(EXCLUDED.licenses) > 0 THEN EXCLUDED.licenses ELSE components.licenses END
RETURNING *;

-- name: AttachComponentToSnapshot :exec
-- labels accumulates rather than overwrites: one snapshot ingests several SBOM
-- artifacts, and a component present in more than one must record all of them.
-- `||` is a shallow merge, which is why provenance is stored as a flat key set
-- ("sbom:<filename>": true) instead of a nested array — an array-valued key
-- would be replaced by the last writer, silently losing the earlier artifact.
INSERT INTO snapshot_components (snapshot_id, component_id, labels)
VALUES (sqlc.arg(snapshot_id), sqlc.arg(component_id), COALESCE(sqlc.arg(labels)::jsonb, '{}'::jsonb))
ON CONFLICT (snapshot_id, component_id) DO UPDATE
SET labels = snapshot_components.labels || EXCLUDED.labels;

-- name: UpsertComponentDependency :exec
INSERT INTO component_dependencies (snapshot_id, component_id, depends_on_component_id)
VALUES ($1, $2, $3)
ON CONFLICT (snapshot_id, component_id, depends_on_component_id) DO NOTHING;

-- name: UpsertSnapshotDependencyRoot :exec
INSERT INTO snapshot_dependency_roots (snapshot_id, component_id)
VALUES ($1, $2)
ON CONFLICT (snapshot_id) DO UPDATE SET component_id = EXCLUDED.component_id;

-- name: GetSnapshotDependencyRoot :one
SELECT c.purl
FROM snapshot_dependency_roots sdr
JOIN components c ON c.id = sdr.component_id
WHERE sdr.snapshot_id = $1;

-- name: ListComponentDependencyEdgesBySnapshot :many
SELECT source.purl AS ref, dependency.purl AS depends_on
FROM component_dependencies cd
JOIN components source ON source.id = cd.component_id
JOIN components dependency ON dependency.id = cd.depends_on_component_id
WHERE cd.snapshot_id = $1
ORDER BY source.purl ASC, dependency.purl ASC;

-- name: ListSnapshotComponentLabels :many
-- The provenance labels of every component in a snapshot (ADR-045 §5):
-- which artifacts reported it and, from the built-in extractor, its
-- relationship, scopes, modules and registry.
SELECT component_id, labels FROM snapshot_components WHERE snapshot_id = $1;

-- name: CopySnapshotExtractionComponents :execrows
-- Digest reuse without a stored document (ADR-045 §4.1): copies the
-- built-in extractor's rows from an earlier snapshot, keeping only the
-- labels the extractor wrote (its source label and the provenance keys),
-- never another artifact's.
INSERT INTO snapshot_components (snapshot_id, component_id, labels)
SELECT sqlc.arg(to_snapshot_id), sc.component_id,
       (SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{}'::jsonb)
        FROM jsonb_each(sc.labels) e
        WHERE e.key = sqlc.arg(source_label)::text
           OR e.key LIKE 'relationship:%' OR e.key LIKE 'scope:%' OR e.key LIKE 'module:%'
           OR e.key LIKE 'path:%' OR e.key LIKE 'resolution:%' OR e.key LIKE 'registry:%'
           OR e.key LIKE 'constraint:%')
FROM snapshot_components sc
WHERE sc.snapshot_id = sqlc.arg(from_snapshot_id) AND sc.labels ? sqlc.arg(source_label)::text
ON CONFLICT (snapshot_id, component_id) DO UPDATE
SET labels = snapshot_components.labels || EXCLUDED.labels;

-- name: CopySnapshotExtractionDependencies :exec
INSERT INTO component_dependencies (snapshot_id, component_id, depends_on_component_id)
SELECT sqlc.arg(to_snapshot_id), cd.component_id, cd.depends_on_component_id
FROM component_dependencies cd
JOIN snapshot_components a ON a.snapshot_id = cd.snapshot_id AND a.component_id = cd.component_id AND a.labels ? sqlc.arg(source_label)::text
JOIN snapshot_components b ON b.snapshot_id = cd.snapshot_id AND b.component_id = cd.depends_on_component_id AND b.labels ? sqlc.arg(source_label)::text
WHERE cd.snapshot_id = sqlc.arg(from_snapshot_id)
ON CONFLICT (snapshot_id, component_id, depends_on_component_id) DO NOTHING;

-- name: CopySnapshotDependencyRoot :exec
INSERT INTO snapshot_dependency_roots (snapshot_id, component_id)
SELECT sqlc.arg(to_snapshot_id), r.component_id FROM snapshot_dependency_roots r WHERE r.snapshot_id = sqlc.arg(from_snapshot_id)
ON CONFLICT (snapshot_id) DO NOTHING;
