-- name: UpsertComponent :one
INSERT INTO components (purl, name, version, ecosystem, licenses)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (purl, version) DO UPDATE SET
	name = EXCLUDED.name,
	ecosystem = EXCLUDED.ecosystem,
	licenses = CASE WHEN cardinality(EXCLUDED.licenses) > 0 THEN EXCLUDED.licenses ELSE components.licenses END
RETURNING *;

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
