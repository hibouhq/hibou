-- name: CreateAuditLog :one
INSERT INTO audit_logs (actor_id, actor_type, actor_display, action, resource_type, resource_id, org_id, context, ip_address, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: ListAuditLogs :many
SELECT * FROM audit_logs
WHERE org_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListRecentAuditLogsByOrg :many
SELECT * FROM audit_logs
WHERE org_id = $1 AND created_at >= $2
ORDER BY created_at DESC
LIMIT $3;

-- name: ListAuditLogsByResource :many
SELECT * FROM audit_logs
WHERE resource_type = $1 AND resource_id = $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: ListAuditLogsByActor :many
SELECT * FROM audit_logs
WHERE actor_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountAuditLogsByOrg :one
SELECT COUNT(*)::bigint FROM audit_logs WHERE org_id = $1;
