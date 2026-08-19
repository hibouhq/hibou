-- name: UpsertFindingDispute :one
-- One dispute per (repo, fingerprint): re-disputing replaces the reason and
-- refreshes the author, it never stacks rows.
INSERT INTO finding_disputes (repo_id, fingerprint, reason, disputed_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (repo_id, fingerprint) DO UPDATE SET
    reason = EXCLUDED.reason,
    disputed_by = EXCLUDED.disputed_by,
    created_at = now()
RETURNING *;

-- name: DeleteFindingDispute :execrows
DELETE FROM finding_disputes
WHERE repo_id = $1 AND fingerprint = $2;

-- name: GetFindingDispute :one
SELECT * FROM finding_disputes
WHERE repo_id = $1 AND fingerprint = $2;

-- name: ListFindingDisputesByRepo :many
SELECT * FROM finding_disputes
WHERE repo_id = $1
ORDER BY created_at DESC;
