-- Statements are insert-only (ADR-053 §4a): a change inserts a row that
-- supersedes the current one, a withdrawal inserts a withdrawn row. Readers
-- see the current, non-withdrawn statement of each scope unless they ask for
-- history.

-- name: CreateVEXStatement :one
INSERT INTO vex_statements (
    org_id,
    advisory_id,
    repo_id,
    component_purl,
    release_id,
    version_range,
    status,
    justification,
    impact_statement,
    action_statement,
    source,
    source_document_url,
    supplier,
    evidence,
    supersedes,
    withdrawn,
    approved_by,
    approved_at,
    created_by,
    expires_at
)
VALUES (
    sqlc.arg(org_id),
    sqlc.arg(advisory_id),
    sqlc.arg(repo_id),
    sqlc.arg(component_purl),
    sqlc.arg(release_id),
    sqlc.arg(version_range),
    sqlc.arg(status),
    sqlc.arg(justification),
    sqlc.arg(impact_statement),
    sqlc.arg(action_statement),
    sqlc.arg(source),
    sqlc.arg(source_document_url),
    sqlc.arg(supplier),
    sqlc.arg(evidence),
    sqlc.arg(supersedes),
    sqlc.arg(withdrawn),
    sqlc.arg(approved_by),
    sqlc.arg(approved_at),
    sqlc.arg(created_by),
    sqlc.arg(expires_at)
)
RETURNING *;

-- name: MarkVEXStatementSuperseded :execrows
-- Stamps the current row of a scope before its successor is inserted; the
-- partial unique index then admits the successor. Content stays untouched.
UPDATE vex_statements
SET superseded_at = NOW()
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
  AND superseded_at IS NULL;

-- name: GetVEXStatementByID :one
SELECT *
FROM vex_statements
WHERE id = $1;

-- name: GetCurrentVEXStatementForScope :one
SELECT *
FROM vex_statements
WHERE org_id = sqlc.arg(org_id)
  AND advisory_id = sqlc.arg(advisory_id)
  AND repo_id IS NOT DISTINCT FROM sqlc.narg(repo_id)
  AND component_purl IS NOT DISTINCT FROM sqlc.narg(component_purl)
  AND release_id IS NOT DISTINCT FROM sqlc.narg(release_id)
  AND version_range IS NOT DISTINCT FROM sqlc.narg(version_range)
  AND superseded_at IS NULL
FOR UPDATE;

-- name: ListVEXStatementHistory :many
-- The chain a statement belongs to, oldest first.
WITH RECURSIVE back AS (
    SELECT vs.* FROM vex_statements vs WHERE vs.id = sqlc.arg(id) AND vs.org_id = sqlc.arg(org_id)
    UNION ALL
    SELECT prev.* FROM vex_statements prev JOIN back ON back.supersedes = prev.id
), fwd AS (
    SELECT vs.* FROM vex_statements vs WHERE vs.id = sqlc.arg(id) AND vs.org_id = sqlc.arg(org_id)
    UNION ALL
    SELECT nxt.* FROM vex_statements nxt JOIN fwd ON nxt.supersedes = fwd.id
)
SELECT DISTINCT * FROM (SELECT * FROM back UNION SELECT * FROM fwd) chain
ORDER BY created_at ASC;

-- name: ListVEXStatementsByOrg :many
SELECT *
FROM vex_statements
WHERE org_id = $1
  AND superseded_at IS NULL
  AND NOT withdrawn
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListVEXStatementsByRepo :many
SELECT *
FROM vex_statements
WHERE org_id = $1
  AND repo_id = $2
  AND superseded_at IS NULL
  AND NOT withdrawn
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;

-- name: ListVEXStatementsByAdvisory :many
SELECT *
FROM vex_statements
WHERE org_id = $1
  AND advisory_id = $2
  AND superseded_at IS NULL
  AND NOT withdrawn
ORDER BY created_at DESC;

-- name: ListVEXStatementsForAdvisoryRepo :many
-- Every current statement an incident's scope can rely on: org-wide,
-- repository-wide, per component, per release, per version range.
SELECT *
FROM vex_statements
WHERE org_id = sqlc.arg(org_id)
  AND advisory_id = sqlc.arg(advisory_id)
  AND (repo_id IS NULL OR repo_id = sqlc.arg(repo_id))
  AND superseded_at IS NULL
  AND NOT withdrawn
  AND (expires_at IS NULL OR expires_at >= NOW())
ORDER BY created_at DESC;

-- name: GetEffectiveVEXStatus :one
-- Gates judge snapshots, not releases: only statements without a product
-- axis apply here; release- and range-scoped statements speak about shipped
-- versions (ADR-053 §4a).
SELECT *
FROM vex_statements
WHERE org_id = sqlc.arg(org_id)
  AND advisory_id = sqlc.arg(advisory_id)
  AND (repo_id IS NULL OR repo_id = sqlc.narg(repo_id))
  AND (component_purl IS NULL OR component_purl = sqlc.narg(component_purl))
  AND release_id IS NULL
  AND version_range IS NULL
  AND superseded_at IS NULL
  AND NOT withdrawn
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
  AND superseded_at IS NULL
  AND NOT withdrawn
ORDER BY expires_at ASC;

-- name: ListUnapprovedVEXStatementsByOrg :many
SELECT *
FROM vex_statements
WHERE org_id = $1
  AND superseded_at IS NULL
  AND NOT withdrawn
  AND approved_by IS NULL
ORDER BY created_at ASC
LIMIT $2;

-- name: CountVEXStatementsByOrg :one
SELECT COUNT(*)::bigint
FROM vex_statements
WHERE org_id = $1
  AND superseded_at IS NULL
  AND NOT withdrawn;

-- name: CountVEXStatementsByRepo :one
SELECT COUNT(*)::bigint
FROM vex_statements
WHERE org_id = $1
  AND repo_id = $2
  AND superseded_at IS NULL
  AND NOT withdrawn;

-- name: CreateFirstPartyAdvisory :one
INSERT INTO first_party_advisories (org_id, repo_id, advisory_id, product_purl, product_cpe, affected_range, promoted_from, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListFirstPartyAdvisoriesByRepo :many
SELECT f.*, a.canonical_id, a.title
FROM first_party_advisories f
JOIN advisories a ON a.id = f.advisory_id
WHERE f.repo_id = $1
ORDER BY f.created_at DESC;

-- name: GetFirstPartyAdvisory :one
SELECT * FROM first_party_advisories WHERE repo_id = $1 AND advisory_id = $2;
