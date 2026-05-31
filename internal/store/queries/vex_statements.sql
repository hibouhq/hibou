-- name: CreateVEXStatement :one
INSERT INTO vex_statements (
    org_id,
    advisory_id,
    repo_id,
    component_purl,
    status,
    justification,
    impact_statement,
    action_statement,
    source,
    source_document_url,
    supplier,
    created_by,
    expires_at
)
VALUES (
    sqlc.arg(org_id),
    sqlc.arg(advisory_id),
    sqlc.arg(repo_id),
    sqlc.arg(component_purl),
    sqlc.arg(status),
    sqlc.arg(justification),
    sqlc.arg(impact_statement),
    sqlc.arg(action_statement),
    sqlc.arg(source),
    sqlc.arg(source_document_url),
    sqlc.arg(supplier),
    sqlc.arg(created_by),
    sqlc.arg(expires_at)
)
RETURNING *;

-- name: UpdateVEXStatement :one
UPDATE vex_statements
SET
    repo_id = sqlc.arg(repo_id),
    component_purl = sqlc.arg(component_purl),
    status = sqlc.arg(status),
    justification = sqlc.arg(justification),
    impact_statement = sqlc.arg(impact_statement),
    action_statement = sqlc.arg(action_statement),
    source = sqlc.arg(source),
    source_document_url = sqlc.arg(source_document_url),
    supplier = sqlc.arg(supplier),
    expires_at = sqlc.arg(expires_at),
    updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
RETURNING *;

-- name: GetVEXStatementByID :one
SELECT *
FROM vex_statements
WHERE id = $1;

-- name: ListVEXStatementsByOrg :many
SELECT *
FROM vex_statements
WHERE org_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListVEXStatementsByRepo :many
SELECT *
FROM vex_statements
WHERE org_id = $1
  AND repo_id = $2
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: ListVEXStatementsByAdvisory :many
SELECT *
FROM vex_statements
WHERE org_id = $1
  AND advisory_id = $2
ORDER BY created_at DESC;

-- name: DeleteVEXStatement :exec
DELETE FROM vex_statements
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id);

-- name: GetEffectiveVEXStatus :one
SELECT *
FROM vex_statements
WHERE org_id = sqlc.arg(org_id)
  AND advisory_id = sqlc.arg(advisory_id)
  AND (repo_id IS NULL OR repo_id = sqlc.narg(repo_id))
  AND (component_purl IS NULL OR component_purl = sqlc.narg(component_purl))
  AND (expires_at IS NULL OR expires_at >= NOW())
ORDER BY CASE
    WHEN component_purl = sqlc.narg(component_purl) THEN 0
    WHEN repo_id = sqlc.narg(repo_id) THEN 1
    ELSE 2
END,
updated_at DESC,
created_at DESC
LIMIT 1;

-- name: ListExpiredVEXStatements :many
SELECT *
FROM vex_statements
WHERE expires_at IS NOT NULL
  AND expires_at < NOW()
ORDER BY expires_at ASC;

-- name: CountVEXStatementsByOrg :one
SELECT COUNT(*)::bigint
FROM vex_statements
WHERE org_id = $1;

-- name: CountVEXStatementsByRepo :one
SELECT COUNT(*)::bigint
FROM vex_statements
WHERE org_id = $1
  AND repo_id = $2;
