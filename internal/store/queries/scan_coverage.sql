-- name: DeleteRepoScanCoverage :exec
DELETE FROM scan_coverage WHERE repo_id = $1;

-- name: InsertRepoScanCoverage :exec
INSERT INTO scan_coverage (repo_id, scanner_id, state, reason, configured, required, enforcement, last_run_at, last_commit, computed_at)
SELECT sqlc.arg(repo_id)::uuid, c.scanner_id, c.state, COALESCE(c.reason, ''), c.configured, COALESCE(c.required, false),
       COALESCE(c.enforcement, ''), c.last_run_at, COALESCE(c.last_commit, ''), now()
FROM jsonb_to_recordset(sqlc.arg(cells)::jsonb) AS c(
    scanner_id text, state text, reason text, configured text, required boolean,
    enforcement text, last_run_at timestamptz, last_commit text
);

-- name: ListOrgScanCoverage :many
-- One page of the org matrix: required gaps first, then by repository.
SELECT sc.*, r.slug AS repo_slug, r.name AS repo_name
FROM scan_coverage sc
JOIN repositories r ON r.id = sc.repo_id
WHERE r.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(state)::text = '' OR sc.state = sqlc.arg(state)::text)
  AND (sqlc.arg(scanner_id)::text = '' OR sc.scanner_id = sqlc.arg(scanner_id)::text)
  AND (NOT sqlc.arg(required_only)::boolean OR sc.required)
  AND sc.state <> 'not_applicable'
ORDER BY (sc.required AND sc.state NOT IN ('covered', 'pending', 'exempt', 'disabled')) DESC, r.slug, sc.scanner_id
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: SummarizeOrgScanCoverage :many
-- Counts per state over applicable cells; not-applicable cells are counted
-- apart so the denominator is disclosed, not hidden (ADR-035 §6).
SELECT sc.state, sc.required, COUNT(*)::bigint AS cells
FROM scan_coverage sc
JOIN repositories r ON r.id = sc.repo_id
WHERE r.org_id = $1
GROUP BY sc.state, sc.required
ORDER BY sc.state;

-- name: ListProducerRunsForRef :many
-- Recent runs on a ref with their snapshot commit, newest first.
SELECT pr.*, s.commit_sha
FROM producer_runs pr
JOIN snapshots s ON s.id = pr.snapshot_id
WHERE s.ref_id = $1 AND s.status IN ('complete', 'active')
ORDER BY pr.created_at DESC
LIMIT 500;
