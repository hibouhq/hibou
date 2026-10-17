-- name: UpsertPackagePolicyAcceptance :one
INSERT INTO package_policy_acceptances (org_id, repo_id, purl, reason, accepted_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.narg(repo_id), sqlc.arg(purl), sqlc.arg(reason), sqlc.narg(accepted_by), sqlc.narg(expires_at))
ON CONFLICT (org_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), purl) DO UPDATE SET
    reason = EXCLUDED.reason,
    accepted_by = EXCLUDED.accepted_by,
    expires_at = EXCLUDED.expires_at,
    created_at = now()
RETURNING *;

-- name: DeletePackagePolicyAcceptance :execrows
DELETE FROM package_policy_acceptances
WHERE org_id = sqlc.arg(org_id)
    AND purl = sqlc.arg(purl)
    AND COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE(sqlc.narg(repo_id), '00000000-0000-0000-0000-000000000000'::uuid);

-- name: ListPackagePolicyAcceptancesForPurls :many
-- Org-wide rows and the given repository's rows for the purls asked,
-- unexpired. The caller decides precedence (a repo row is more specific).
SELECT * FROM package_policy_acceptances
WHERE org_id = sqlc.arg(org_id)
    AND purl = ANY(sqlc.arg(purls)::text[])
    AND (repo_id IS NULL OR repo_id = sqlc.narg(repo_id))
    AND (expires_at IS NULL OR expires_at > now());

-- name: ListPackagePolicyAcceptancesByOrg :many
SELECT * FROM package_policy_acceptances
WHERE org_id = sqlc.arg(org_id)
ORDER BY created_at DESC
LIMIT sqlc.arg(row_limit);
