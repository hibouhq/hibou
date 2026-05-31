-- name: CreateSecretFinding :one
INSERT INTO secret_findings (
    snapshot_id,
    tool,
    rule_id,
    severity,
    status,
    discovery_context,
    file_path,
    start_line,
    end_line,
    secret_type,
    secret_hash,
    commit_sha,
    author_email,
    verified,
    metadata,
    fingerprint
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10,
    $11,
    $12,
    $13,
    $14,
    $15,
    $16
)
RETURNING *;

-- name: GetSecretFindingByID :one
SELECT * FROM secret_findings WHERE id = $1;

-- name: ListSecretFindingsBySnapshot :many
SELECT * FROM secret_findings
WHERE snapshot_id = $1
ORDER BY severity, created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountSecretFindingsBySnapshot :one
SELECT COUNT(*)::bigint FROM secret_findings WHERE snapshot_id = $1;

-- name: ListSecretFindingsByRepo :many
-- List all secret findings for latest snapshots in a repository.
SELECT sf.* FROM secret_findings sf
JOIN snapshots s ON sf.snapshot_id = s.id
JOIN refs r ON s.ref_id = r.id
WHERE r.repo_id = $1
ORDER BY sf.severity, sf.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountSecretFindingsByRepo :one
SELECT COUNT(*)::bigint FROM secret_findings sf
JOIN snapshots s ON sf.snapshot_id = s.id
JOIN refs r ON s.ref_id = r.id
WHERE r.repo_id = $1;

-- name: ListAllSecretFindingsBySnapshot :many
SELECT * FROM secret_findings
WHERE snapshot_id = $1
ORDER BY severity, created_at DESC;

-- name: ListSecretFindingSummaryBySnapshot :many
SELECT severity, COUNT(*)::bigint AS count
FROM secret_findings
WHERE snapshot_id = $1
GROUP BY severity
ORDER BY severity;

-- name: BulkUpdateSecretFindingStatus :exec
UPDATE secret_findings
SET status = $2, status_note = $3
WHERE id = ANY($1::uuid[]);

-- name: GetSecretFindingByFingerprint :one
SELECT * FROM secret_findings
WHERE snapshot_id = $1 AND fingerprint = $2;

-- name: UpdateSecretFindingStatus :one
UPDATE secret_findings
SET status = $2, status_note = $3
WHERE id = $1
RETURNING *;

-- name: UpsertSecretFindingSource :one
INSERT INTO secret_finding_sources (finding_id, tool, rule_id, metadata)
VALUES ($1, $2, $3, $4)
ON CONFLICT (finding_id, tool)
DO UPDATE SET last_seen_at = NOW(), scan_count = secret_finding_sources.scan_count + 1, rule_id = $3, metadata = $4
RETURNING *;

-- name: ListSecretFindingSourcesByFinding :many
SELECT * FROM secret_finding_sources WHERE finding_id = $1 ORDER BY first_seen_at;

-- name: SecretToolStats :many
SELECT tool, COUNT(DISTINCT finding_id)::bigint AS finding_count
FROM secret_finding_sources
GROUP BY tool
ORDER BY finding_count DESC;

-- name: SecretToolOverlap :many
SELECT s1.tool AS tool_a, s2.tool AS tool_b, COUNT(*)::bigint AS shared_findings
FROM secret_finding_sources s1
JOIN secret_finding_sources s2 ON s1.finding_id = s2.finding_id AND s1.tool < s2.tool
GROUP BY s1.tool, s2.tool
ORDER BY shared_findings DESC;

-- name: SecretUniqueByTool :many
SELECT sfs.tool, COUNT(*)::bigint AS unique_findings
FROM secret_finding_sources sfs
WHERE NOT EXISTS (
    SELECT 1 FROM secret_finding_sources other
    WHERE other.finding_id = sfs.finding_id AND other.tool != sfs.tool
)
GROUP BY sfs.tool
ORDER BY unique_findings DESC;
