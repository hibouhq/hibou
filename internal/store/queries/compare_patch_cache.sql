-- name: GetComparePatchCache :one
SELECT * FROM compare_patch_cache
WHERE repo_id = $1 AND base_sha = $2 AND head_sha = $3;

-- name: UpsertComparePatchCache :one
-- Immutable inputs, so a conflicting row is identical by construction; the
-- upsert exists only to make concurrent first-loads idempotent.
INSERT INTO compare_patch_cache (repo_id, base_sha, head_sha, truncated, payload)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (repo_id, base_sha, head_sha)
DO UPDATE SET truncated = EXCLUDED.truncated, payload = EXCLUDED.payload
RETURNING *;

-- name: DeleteComparePatchCacheForCommit :exec
-- Called when a snapshot is purged: any comparison involving its commit is no
-- longer reachable from the UI.
DELETE FROM compare_patch_cache
WHERE repo_id = $1 AND (base_sha = $2 OR head_sha = $2);
