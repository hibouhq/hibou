-- name: SearchAdvisories :many
SELECT DISTINCT a.*
FROM advisories a
JOIN vuln_matches vm ON vm.advisory_id = a.id
JOIN snapshots s ON s.id = vm.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND (a.canonical_id ILIKE $2 ESCAPE '\\' OR a.title ILIKE $2 ESCAPE '\\')
ORDER BY a.created_at DESC
LIMIT $3 OFFSET $4;

-- name: CountSearchAdvisories :one
SELECT COUNT(DISTINCT a.id)::bigint
FROM advisories a
JOIN vuln_matches vm ON vm.advisory_id = a.id
JOIN snapshots s ON s.id = vm.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND (a.canonical_id ILIKE $2 ESCAPE '\\' OR a.title ILIKE $2 ESCAPE '\\');

-- name: SearchAdvisoriesBySeverity :many
SELECT DISTINCT a.*
FROM advisories a
JOIN vuln_matches vm ON vm.advisory_id = a.id
JOIN snapshots s ON s.id = vm.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND (a.canonical_id ILIKE $2 ESCAPE '\\' OR a.title ILIKE $2 ESCAPE '\\')
  AND a.severity::text = $3
ORDER BY a.created_at DESC
LIMIT $4 OFFSET $5;

-- name: CountSearchAdvisoriesBySeverity :one
SELECT COUNT(DISTINCT a.id)::bigint
FROM advisories a
JOIN vuln_matches vm ON vm.advisory_id = a.id
JOIN snapshots s ON s.id = vm.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND (a.canonical_id ILIKE $2 ESCAPE '\\' OR a.title ILIKE $2 ESCAPE '\\')
  AND a.severity::text = $3;

-- name: SearchComponents :many
SELECT DISTINCT c.*
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots s ON s.id = sc.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1 AND (c.name ILIKE $2 ESCAPE '\\' OR c.purl ILIKE $2 ESCAPE '\\')
ORDER BY c.name ASC LIMIT $3 OFFSET $4;

-- name: CountSearchComponents :one
SELECT COUNT(DISTINCT c.id)::bigint
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots s ON s.id = sc.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1 AND (c.name ILIKE $2 ESCAPE '\\' OR c.purl ILIKE $2 ESCAPE '\\');

-- name: SearchFindings :many
SELECT f.*
FROM findings f
JOIN snapshots s ON s.id = f.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1 AND (f.rule_id ILIKE $2 ESCAPE '\\' OR f.tool ILIKE $2 ESCAPE '\\' OR f.message ILIKE $2 ESCAPE '\\')
ORDER BY f.created_at DESC LIMIT $3 OFFSET $4;

-- name: CountSearchFindings :one
SELECT COUNT(*)::bigint
FROM findings f
JOIN snapshots s ON s.id = f.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1 AND (f.rule_id ILIKE $2 ESCAPE '\\' OR f.tool ILIKE $2 ESCAPE '\\' OR f.message ILIKE $2 ESCAPE '\\');

-- name: SearchFindingsBySeverity :many
SELECT f.*
FROM findings f
JOIN snapshots s ON s.id = f.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND (f.rule_id ILIKE $2 ESCAPE '\\' OR f.tool ILIKE $2 ESCAPE '\\' OR f.message ILIKE $2 ESCAPE '\\')
  AND f.severity::text = $3
ORDER BY f.created_at DESC LIMIT $4 OFFSET $5;

-- name: CountSearchFindingsBySeverity :one
SELECT COUNT(*)::bigint
FROM findings f
JOIN snapshots s ON s.id = f.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND (f.rule_id ILIKE $2 ESCAPE '\\' OR f.tool ILIKE $2 ESCAPE '\\' OR f.message ILIKE $2 ESCAPE '\\')
  AND f.severity::text = $3;

-- name: SearchClients :many
SELECT * FROM clients WHERE org_id = $1 AND name ILIKE $2 ESCAPE '\\' ORDER BY name ASC LIMIT $3 OFFSET $4;

-- name: CountSearchClients :one
SELECT COUNT(*)::bigint FROM clients WHERE org_id = $1 AND name ILIKE $2 ESCAPE '\\';
