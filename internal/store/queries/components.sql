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
