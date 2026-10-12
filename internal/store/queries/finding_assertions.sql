-- name: ConfirmFindingAssertion :one
-- Re-assert (ADR-034 §4): updates "last confirmed" and reopens an assertion
-- that was closed — the agent says the problem is still there.
INSERT INTO finding_assertions (repo_id, fingerprint, last_confirmed_at, last_confirmed_by, last_confirmed_api_key_id, updated_at)
VALUES ($1, $2, now(), sqlc.narg(confirmed_by), sqlc.narg(confirmed_api_key_id), now())
ON CONFLICT (repo_id, fingerprint) DO UPDATE SET
    last_confirmed_at = now(),
    last_confirmed_by = EXCLUDED.last_confirmed_by,
    last_confirmed_api_key_id = EXCLUDED.last_confirmed_api_key_id,
    closed_kind = NULL,
    closed_at = NULL,
    closed_by = NULL,
    closed_api_key_id = NULL,
    closed_reason = NULL,
    updated_at = now()
RETURNING *;

-- name: CloseFindingAssertion :one
INSERT INTO finding_assertions (repo_id, fingerprint, closed_kind, closed_at, closed_by, closed_api_key_id, closed_reason, updated_at)
VALUES ($1, $2, sqlc.arg(kind), now(), sqlc.narg(closed_by), sqlc.narg(closed_api_key_id), sqlc.arg(reason), now())
ON CONFLICT (repo_id, fingerprint) DO UPDATE SET
    closed_kind = EXCLUDED.closed_kind,
    closed_at = now(),
    closed_by = EXCLUDED.closed_by,
    closed_api_key_id = EXCLUDED.closed_api_key_id,
    closed_reason = EXCLUDED.closed_reason,
    updated_at = now()
RETURNING *;

-- name: GetFindingAssertion :one
SELECT * FROM finding_assertions WHERE repo_id = $1 AND fingerprint = $2;

-- name: ListClosedAssertionFingerprints :many
SELECT fingerprint FROM finding_assertions WHERE repo_id = $1 AND closed_kind IS NOT NULL;

-- name: SetAssertionRowsStatus :execrows
-- Applies a decision to the assertion's rows in the latest snapshot of each
-- ref (where it is currently open), so it stops counting now rather than at
-- the next commit. Older snapshots keep their history.
UPDATE vulnerabilities v
SET status = sqlc.arg(status)::vulnerability_status,
    resolved_at = CASE WHEN sqlc.arg(status)::text = 'resolved' THEN now() ELSE NULL END,
    resolved_by = CASE WHEN sqlc.arg(status)::text = 'resolved' THEN sqlc.narg(resolved_by)::uuid ELSE NULL END,
    updated_at = now()
WHERE v.repo_id = sqlc.arg(repo_id)
  AND v.fingerprint = sqlc.arg(fingerprint)
  AND v.origin IN ('human', 'agent')
  AND v.snapshot_id IN (
      SELECT DISTINCT ON (s.ref_id) s.id
      FROM snapshots s
      JOIN refs r ON r.id = s.ref_id
      WHERE r.repo_id = sqlc.arg(repo_id)
      ORDER BY s.ref_id, s.created_at DESC
  );
