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
    last_error,
    claims_base_sha
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
    claims_base_sha = EXCLUDED.claims_base_sha,
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

-- name: ReplacePRCheckResolvedFingerprints :exec
-- The set of findings this PR resolves versus its base, refreshed on every
-- gate publish. Persisted so the findings list can answer "a PR already fixes
-- this" with a join instead of recomputing deltas per render.
WITH cleared AS (
    DELETE FROM pr_check_resolved_fingerprints WHERE pr_check_id = $1
)
INSERT INTO pr_check_resolved_fingerprints (pr_check_id, fingerprint)
SELECT $1, unnest(sqlc.arg(fingerprints)::text[])
ON CONFLICT DO NOTHING;

-- name: ListFixingPullRequests :many
-- Open PRs whose latest published gate resolves the given fingerprints.
SELECT f.fingerprint, r.name AS ref_name, r.pr_number, r.pr_title, c.claims_base_sha
FROM pr_check_resolved_fingerprints f
JOIN pr_checks c ON c.id = f.pr_check_id
JOIN refs r ON r.id = c.ref_id
WHERE c.repo_id = $1
  AND f.fingerprint = ANY(sqlc.arg(fingerprints)::text[])
  AND r.ref_type = 'pull_request'
  AND COALESCE(r.pr_state, 'open') = 'open'
ORDER BY r.pr_number;
