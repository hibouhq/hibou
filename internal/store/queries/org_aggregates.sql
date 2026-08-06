-- name: CountScansByOrg :one
SELECT COUNT(*)::bigint
FROM scans sc
JOIN snapshots s ON s.id = sc.snapshot_id
WHERE s.org_id = $1;

-- name: LatestScanCompletedAtByOrg :one
SELECT COALESCE(MAX(sc.completed_at), '1970-01-01T00:00:00Z'::timestamptz)
FROM scans sc
JOIN snapshots s ON s.id = sc.snapshot_id
WHERE s.org_id = $1
  AND sc.status = 'complete';

-- name: CountMalwareAdvisoriesByOrg :one
SELECT COUNT(DISTINCT a.id)::bigint
FROM advisories a
JOIN vulnerabilities v ON v.advisory_id = a.id
WHERE v.org_id = $1
  AND v.type = 'malware'
  AND v.status NOT IN ('resolved', 'suppressed')
  AND a.is_malware = TRUE
  AND NOT EXISTS (
    SELECT 1 FROM finding_acceptances fa
    WHERE fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
      AND fa.reason_kind = 'false_positive'
      AND (fa.expires_at IS NULL OR fa.expires_at > now())
  );

-- name: CountDistinctComponentsByOrg :one
SELECT COUNT(DISTINCT c.id)::bigint
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots s ON s.id = sc.snapshot_id
WHERE s.org_id = $1;
