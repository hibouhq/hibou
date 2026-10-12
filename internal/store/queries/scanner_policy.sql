-- name: ListRepoScannerSettings :many
SELECT * FROM repo_scanner_settings WHERE repo_id = $1 ORDER BY scanner_id;

-- name: UpsertRepoScannerSetting :one
INSERT INTO repo_scanner_settings (repo_id, scanner_id, mode, updated_by, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (repo_id, scanner_id) DO UPDATE SET mode = EXCLUDED.mode, updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING *;

-- name: ListScannerRequirements :many
SELECT * FROM scanner_requirements WHERE org_id = $1 ORDER BY language, capability;

-- name: UpsertScannerRequirement :one
INSERT INTO scanner_requirements (org_id, language, capability, scanner_ids, freshness_days, enforcement, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, language, capability) DO UPDATE SET
    scanner_ids = EXCLUDED.scanner_ids,
    freshness_days = EXCLUDED.freshness_days,
    enforcement = EXCLUDED.enforcement
RETURNING *;

-- name: DeleteScannerRequirement :execrows
DELETE FROM scanner_requirements WHERE id = $1 AND org_id = $2;

-- name: ListCoverageExceptionsByRepo :many
SELECT * FROM coverage_exceptions WHERE repo_id = $1 ORDER BY created_at DESC;

-- name: ListPendingCoverageExceptionsByOrg :many
SELECT ce.*, r.slug AS repo_slug
FROM coverage_exceptions ce
JOIN repositories r ON r.id = ce.repo_id
WHERE r.org_id = $1 AND ce.status = 'requested'
ORDER BY ce.created_at;

-- name: CreateCoverageException :one
INSERT INTO coverage_exceptions (repo_id, requirement_id, scope, reason, requested_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: DecideCoverageException :one
UPDATE coverage_exceptions ce
SET status = sqlc.arg(status), decided_by = sqlc.narg(decided_by), decided_at = now()
FROM repositories r
WHERE ce.id = sqlc.arg(id) AND r.id = ce.repo_id AND r.org_id = sqlc.arg(org_id) AND ce.status = 'requested'
RETURNING ce.*;
