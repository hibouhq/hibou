-- name: UpsertPRCheck :one
INSERT INTO pr_checks (
    repo_id,
    ref_id,
    head_sha,
    context,
    state,
    conclusion,
    enforcement,
    passed,
    reasons,
    delta_summary,
    external_id,
    target_url,
    forge_synced_at,
    last_error
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (repo_id, head_sha, context) DO UPDATE SET
    ref_id = EXCLUDED.ref_id,
    state = EXCLUDED.state,
    conclusion = EXCLUDED.conclusion,
    enforcement = EXCLUDED.enforcement,
    passed = EXCLUDED.passed,
    reasons = EXCLUDED.reasons,
    delta_summary = EXCLUDED.delta_summary,
    -- keep a previously-stored forge check-run id unless a new one is supplied.
    external_id = CASE WHEN EXCLUDED.external_id <> '' THEN EXCLUDED.external_id ELSE pr_checks.external_id END,
    target_url = EXCLUDED.target_url,
    forge_synced_at = EXCLUDED.forge_synced_at,
    last_error = EXCLUDED.last_error,
    updated_at = NOW()
RETURNING *;

-- name: GetPRCheck :one
SELECT *
FROM pr_checks
WHERE repo_id = $1 AND head_sha = $2 AND context = $3;

-- name: GetLatestPRCheckByRef :one
SELECT *
FROM pr_checks
WHERE ref_id = $1 AND context = $2
ORDER BY updated_at DESC
LIMIT 1;

-- name: ListUnsyncedPRChecks :many
SELECT *
FROM pr_checks
WHERE forge_synced_at IS NULL
ORDER BY created_at ASC
LIMIT $1;

-- name: MarkPRCheckSynced :exec
UPDATE pr_checks
SET forge_synced_at = NOW(), last_error = '', external_id = CASE WHEN sqlc.arg(external_id)::text <> '' THEN sqlc.arg(external_id)::text ELSE external_id END, updated_at = NOW()
WHERE id = $1;
