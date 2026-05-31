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
JOIN vulnerabilities v ON v.advisory_id = a.id
JOIN snapshots s ON s.id = v.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
  AND v.type = 'malware'
  AND v.status NOT IN ('resolved', 'dismissed')
  AND a.is_malware = TRUE;

-- name: CountDistinctComponentsByOrg :one
SELECT COUNT(DISTINCT c.id)::bigint
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots s ON s.id = sc.snapshot_id
JOIN refs r ON r.id = s.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1;
