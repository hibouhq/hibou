-- name: CreateFinding :one
INSERT INTO findings (snapshot_id, tool, rule_id, severity, status, file_path, start_line, end_line, location_hash, message, fingerprint, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetFindingByID :one
SELECT * FROM findings WHERE id = $1;

-- name: ListFindingsBySnapshot :many
SELECT * FROM findings WHERE snapshot_id = $1 ORDER BY severity ASC, file_path ASC LIMIT $2 OFFSET $3;

-- name: CountFindingsBySnapshot :one
SELECT COUNT(*)::bigint FROM findings WHERE snapshot_id = $1;

-- name: ListFindingsBySnapshotAndTool :many
SELECT * FROM findings WHERE snapshot_id = $1 AND tool = $2 ORDER BY severity ASC, file_path ASC LIMIT $3 OFFSET $4;

-- name: CountFindingsBySnapshotAndTool :one
SELECT COUNT(*)::bigint FROM findings WHERE snapshot_id = $1 AND tool = $2;