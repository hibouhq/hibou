-- name: CountVulnMatchesByOrg :one
SELECT COUNT(*)::bigint
FROM vuln_matches vm
JOIN snapshots s ON s.id = vm.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND vm.is_affected = TRUE;

-- name: CountFindingsByOrg :one
SELECT COUNT(*)::bigint
FROM findings f
JOIN snapshots s ON s.id = f.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1;

-- name: CountScansByOrg :one
SELECT COUNT(*)::bigint
FROM scans sc
JOIN snapshots s ON s.id = sc.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1;

-- name: LatestScanCompletedAtByOrg :one
SELECT COALESCE(MAX(sc.completed_at), '1970-01-01T00:00:00Z'::timestamptz)
FROM scans sc
JOIN snapshots s ON s.id = sc.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND sc.status = 'complete';

-- name: CountMalwareAdvisoriesByOrg :one
SELECT COUNT(DISTINCT a.id)::bigint
FROM advisories a
JOIN vuln_matches vm ON vm.advisory_id = a.id
JOIN snapshots s ON s.id = vm.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND a.is_malware = TRUE;

-- name: CountDistinctComponentsByOrg :one
SELECT COUNT(DISTINCT c.id)::bigint
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots s ON s.id = sc.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1;
