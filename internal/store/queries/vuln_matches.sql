-- name: UpsertVulnMatch :one
INSERT INTO vuln_matches (snapshot_id, component_id, advisory_id, affected_range_id, is_affected)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (snapshot_id, component_id, advisory_id) DO UPDATE SET
    affected_range_id = EXCLUDED.affected_range_id,
    is_affected = EXCLUDED.is_affected,
    last_seen_at = NOW()
RETURNING *;

-- name: MarkStaleVulnMatches :exec
UPDATE vuln_matches SET is_affected = FALSE, last_seen_at = NOW()
WHERE snapshot_id = sqlc.arg(snapshot_id) AND is_affected = TRUE
AND id NOT IN (SELECT unnest(sqlc.arg(fresh_match_ids)::uuid[]));

-- name: ListVulnMatchesBySnapshot :many
SELECT * FROM vuln_matches WHERE snapshot_id = $1 AND is_affected = TRUE ORDER BY first_seen_at DESC;

-- name: CountVulnMatchesBySnapshot :one
SELECT COUNT(*)::bigint FROM vuln_matches WHERE snapshot_id = $1 AND is_affected = TRUE AND suppressed = FALSE;

-- name: SuppressVulnMatch :one
UPDATE vuln_matches SET suppressed = TRUE, suppressed_reason = $2 WHERE id = $1 RETURNING *;

-- name: UnsuppressVulnMatch :one
UPDATE vuln_matches SET suppressed = FALSE, suppressed_reason = '' WHERE id = $1 RETURNING *;