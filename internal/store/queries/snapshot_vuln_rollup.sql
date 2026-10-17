-- name: AggregateSnapshotVulnRollup :many
SELECT type::text AS vuln_type, severity::text AS severity, COUNT(*)::bigint AS count
FROM vulnerabilities
WHERE snapshot_id = $1
GROUP BY type, severity;

-- name: UpsertSnapshotVulnRollup :exec
INSERT INTO snapshot_vuln_rollup (snapshot_id, counts, total, rolled_up_at)
VALUES ($1, $2, $3, NOW())
ON CONFLICT (snapshot_id) DO UPDATE SET
    counts = EXCLUDED.counts,
    total = EXCLUDED.total,
    rolled_up_at = NOW();

-- name: GetSnapshotVulnRollup :one
SELECT * FROM snapshot_vuln_rollup WHERE snapshot_id = $1;
