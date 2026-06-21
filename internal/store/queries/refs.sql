-- name: CreateRef :one
INSERT INTO refs (repo_id, name, ref_type, provider_id, merge_target_ref_id, latest_commit_sha)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetRefByID :one
SELECT * FROM refs WHERE id = $1;

-- name: GetRefByRepoAndName :one
SELECT * FROM refs WHERE repo_id = $1 AND name = $2 AND ref_type = $3;

-- name: ListRefsByRepo :many
SELECT * FROM refs WHERE repo_id = $1 ORDER BY name ASC LIMIT $2 OFFSET $3;

-- name: ListRefsEnhanced :many
SELECT
	r.*,
	CASE WHEN s.id IS NULL THEN NULL ELSE s.id END AS latest_snapshot_id,
	COALESCE(s.status::text, '') AS latest_snapshot_status,
	CASE WHEN s.id IS NULL THEN NULL ELSE s.created_at END AS latest_snapshot_date,
	COALESCE(target_ref.name, '') AS merge_target_ref_name
FROM refs r
LEFT JOIN LATERAL (
	SELECT id, status, created_at
	FROM snapshots
	WHERE ref_id = r.id
	ORDER BY created_at DESC
	LIMIT 1
) s ON true
LEFT JOIN refs target_ref ON target_ref.id = r.merge_target_ref_id
WHERE r.repo_id = $1
ORDER BY
	CASE WHEN r.ref_type = 'branch' THEN 0 ELSE 1 END,
	r.name ASC
LIMIT $2 OFFSET $3;

-- name: ListPullRequestRefs :many
SELECT
	r.*,
	CASE WHEN s.id IS NULL THEN NULL ELSE s.id END AS latest_snapshot_id,
	COALESCE(s.status::text, '') AS latest_snapshot_status,
	CASE WHEN s.id IS NULL THEN NULL ELSE s.created_at END AS latest_snapshot_date,
	COALESCE(target_ref.name, '') AS merge_target_ref_name
FROM refs r
LEFT JOIN LATERAL (
	SELECT id, status, created_at
	FROM snapshots
	WHERE ref_id = r.id
	ORDER BY created_at DESC
	LIMIT 1
) s ON true
LEFT JOIN refs target_ref ON target_ref.id = r.merge_target_ref_id
WHERE r.repo_id = $1
  AND r.ref_type = 'pull_request'
  AND (r.pr_state IS NULL OR r.pr_state != 'merged' OR r.pr_merged_at > NOW() - INTERVAL '7 days')
  AND (r.pr_state IS NULL OR r.pr_state != 'closed' OR r.pr_closed_at > NOW() - INTERVAL '7 days')
ORDER BY r.updated_at DESC
LIMIT $2 OFFSET $3;

-- name: CountRefsByRepo :one
SELECT COUNT(*)::bigint FROM refs WHERE repo_id = $1;

-- name: UpdateRefLatestCommit :one
UPDATE refs SET latest_commit_sha = $2, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: UpsertRef :one
INSERT INTO refs (
	repo_id,
	name,
	ref_type,
	provider_id,
	merge_target_ref_id,
	latest_commit_sha,
	pr_number,
	pr_state,
	pr_title,
	pr_source_branch,
	pr_merged_at,
	pr_closed_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (repo_id, name, ref_type) DO UPDATE SET
	provider_id = COALESCE(EXCLUDED.provider_id, refs.provider_id),
	merge_target_ref_id = COALESCE(EXCLUDED.merge_target_ref_id, refs.merge_target_ref_id),
	latest_commit_sha = COALESCE(EXCLUDED.latest_commit_sha, refs.latest_commit_sha),
	pr_number = COALESCE(EXCLUDED.pr_number, refs.pr_number),
	pr_state = COALESCE(EXCLUDED.pr_state, refs.pr_state),
	pr_title = CASE WHEN EXCLUDED.pr_title != '' THEN EXCLUDED.pr_title ELSE refs.pr_title END,
	pr_source_branch = CASE WHEN EXCLUDED.pr_source_branch != '' THEN EXCLUDED.pr_source_branch ELSE refs.pr_source_branch END,
	pr_merged_at = COALESCE(EXCLUDED.pr_merged_at, refs.pr_merged_at),
	pr_closed_at = COALESCE(EXCLUDED.pr_closed_at, refs.pr_closed_at),
	updated_at = NOW()
RETURNING *;

-- name: UpdateRefPRState :one
UPDATE refs
SET pr_state = $2,
	pr_title = $3,
	pr_source_branch = $4,
	pr_merged_at = $5,
	pr_closed_at = $6,
	updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteRef :exec
DELETE FROM refs WHERE id = $1;
