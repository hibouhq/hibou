-- name: UpsertRepoApplicability :one
INSERT INTO repo_applicability (repo_id, ref_name, commit_sha, detection_revision, catalog_revision, status, result)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (repo_id, commit_sha, detection_revision, catalog_revision) DO UPDATE SET
    ref_name = EXCLUDED.ref_name,
    status = EXCLUDED.status,
    result = EXCLUDED.result,
    created_at = now()
RETURNING *;

-- name: GetLatestRepoApplicability :one
SELECT * FROM repo_applicability WHERE repo_id = $1 ORDER BY created_at DESC LIMIT 1;
