-- name: ListComponentLicensesBySnapshots :many
-- One row per (snapshot, component) so the caller can attribute a license to
-- the repo that carries it. Scoped by the snapshot-id array the caller already
-- resolved, so the org filter lives in the resolver rather than being duplicated
-- here — one statement instead of the per-repo N+1 the org components handler
-- still does.
SELECT s.repo_id, c.id, c.purl, c.name, c.version, c.ecosystem, c.licenses
FROM snapshot_components sc
JOIN components c ON c.id = sc.component_id
JOIN snapshots s ON s.id = sc.snapshot_id
WHERE sc.snapshot_id = ANY($1::uuid[]);
