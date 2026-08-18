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

-- name: ListFindingActivity :many
-- Audit entries recorded against ONE fingerprint of ONE repository. The
-- finding-history endpoint is readable by anyone who can read the repository's
-- findings — unlike the org-wide log, which is admin-only — so the scoping
-- lives here rather than in the caller: org, repository, fingerprint, and a
-- caller-supplied action allowlist all bind before a row is returned.
SELECT id, actor_type, actor_display, action, context, created_at
FROM audit_logs
WHERE org_id = $1
  AND context->>'fingerprint' = sqlc.arg(fingerprint)::text
  AND action = ANY(sqlc.arg(actions)::text[])
  AND (
    (resource_type = 'repository' AND resource_id = sqlc.arg(repo_id))
    OR context->>'repo_id' = sqlc.arg(repo_id)
  )
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit);
