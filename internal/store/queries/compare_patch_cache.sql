-- name: GetComparePatchCache :one
SELECT * FROM compare_patch_cache
WHERE repo_id = $1 AND base_sha = $2 AND head_sha = $3;

-- name: UpsertComparePatchCache :one
-- Immutable inputs, so a conflicting row is identical by construction; the
-- upsert exists only to make concurrent first-loads idempotent.
-- A paths-only row (finding presence) is upgraded by a full one, never the
-- reverse.
INSERT INTO compare_patch_cache (repo_id, base_sha, head_sha, truncated, payload, paths_only)
VALUES ($1, $2, $3, $4, $5, sqlc.arg(paths_only))
ON CONFLICT (repo_id, base_sha, head_sha)
DO UPDATE SET truncated = EXCLUDED.truncated, payload = EXCLUDED.payload, paths_only = EXCLUDED.paths_only
WHERE compare_patch_cache.paths_only OR NOT EXCLUDED.paths_only
RETURNING *;

-- name: DeleteComparePatchCacheForCommit :exec
-- Called when a snapshot is purged: any comparison involving its commit is no
-- longer reachable from the UI.
DELETE FROM compare_patch_cache
WHERE repo_id = $1 AND (base_sha = $2 OR head_sha = $2);
