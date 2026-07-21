-- name: CreateVulnerability :one
INSERT INTO vulnerabilities (
    type,
    snapshot_id,
    title,
    description,
    primary_identifier_kind,
    primary_identifier_value,
    original_severity,
    severity,
    status,
    scanner_name,
    scanner_vendor,
    scanner_version,
    scanner_external_id,
    file_path,
    start_line,
    end_line,
    location_hash,
    fingerprint,
    component_id,
    component_name,
    component_version,
    component_purl,
    ecosystem,
    advisory_id,
    affected_range_id,
    language,
    confidence,
    solution,
    has_remediation,
    remediation_link,
    reachability,
    secret_type,
    secret_hash,
    commit_sha,
    author_email,
    verified,
    created_by,
    metadata,
    rule_ref_id
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
    $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
    $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
    $31, $32, $33, $34, $35, $36, $37, $38, $39
)
ON CONFLICT (snapshot_id, type, fingerprint) DO UPDATE SET
    last_seen_at = NOW(),
    severity = EXCLUDED.severity,
    original_severity = EXCLUDED.original_severity,
    status = CASE WHEN vulnerabilities.status IN ('dismissed', 'resolved') THEN vulnerabilities.status ELSE EXCLUDED.status END,
    metadata = EXCLUDED.metadata,
    rule_ref_id = EXCLUDED.rule_ref_id
RETURNING *;

-- name: GetVulnerabilityByID :one
SELECT * FROM vulnerabilities WHERE id = $1;

-- name: ListVulnerabilitiesBySnapshot :many
SELECT * FROM vulnerabilities
WHERE snapshot_id = $1
  AND status = ANY(@statuses::vulnerability_status[])
  AND (COALESCE(array_length(@types::text[], 1), 0) = 0 OR type::text = ANY(@types::text[]))
  AND (COALESCE(array_length(@severities::text[], 1), 0) = 0 OR severity::text = ANY(@severities::text[]))
  AND (COALESCE(array_length(@scanners::text[], 1), 0) = 0 OR scanner_name = ANY(@scanners::text[]))
  AND (COALESCE(array_length(@languages::text[], 1), 0) = 0 OR COALESCE(language, '') = ANY(@languages::text[]))
  AND (@file_query::text = '' OR COALESCE(file_path, '') ILIKE '%' || @file_query::text || '%' ESCAPE '\\')
  AND (@search::text = '' OR (title ILIKE '%' || @search::text || '%' ESCAPE '\\' OR primary_identifier_value ILIKE '%' || @search::text || '%' ESCAPE '\\'))
ORDER BY
  CASE WHEN @sort::text = 'severity_asc' THEN severity_rank END ASC,
  CASE WHEN @sort::text = 'severity_desc' THEN severity_rank END DESC,
  CASE WHEN @sort::text = 'status_asc' THEN status END ASC,
  CASE WHEN @sort::text = 'status_desc' THEN status END DESC,
  CASE WHEN @sort::text = 'detected_asc' THEN detected_at END ASC,
  CASE WHEN @sort::text = 'detected_desc' OR @sort::text = '' THEN detected_at END DESC,
  id DESC
LIMIT $2 OFFSET $3;

-- name: CountVulnerabilitiesBySnapshot :one
SELECT COUNT(*)::bigint FROM vulnerabilities
WHERE snapshot_id = $1
  AND status = ANY(@statuses::vulnerability_status[])
  AND (COALESCE(array_length(@types::text[], 1), 0) = 0 OR type::text = ANY(@types::text[]))
  AND (COALESCE(array_length(@severities::text[], 1), 0) = 0 OR severity::text = ANY(@severities::text[]))
  AND (COALESCE(array_length(@scanners::text[], 1), 0) = 0 OR scanner_name = ANY(@scanners::text[]))
  AND (COALESCE(array_length(@languages::text[], 1), 0) = 0 OR COALESCE(language, '') = ANY(@languages::text[]))
  AND (@file_query::text = '' OR COALESCE(file_path, '') ILIKE '%' || @file_query::text || '%' ESCAPE '\\')
  AND (@search::text = '' OR (title ILIKE '%' || @search::text || '%' ESCAPE '\\' OR primary_identifier_value ILIKE '%' || @search::text || '%' ESCAPE '\\'));

-- name: ListAllVulnerabilitiesBySnapshot :many
SELECT * FROM vulnerabilities
WHERE snapshot_id = $1
ORDER BY
  CASE WHEN type IN ('malware', 'secret') THEN 0 ELSE 1 END,
  severity ASC,
  detected_at DESC;

-- name: ListVulnerabilitiesBySnapshotAndType :many
SELECT * FROM vulnerabilities
WHERE snapshot_id = $1 AND type = $2
  AND status = ANY(@statuses::vulnerability_status[])
ORDER BY severity ASC, detected_at DESC
LIMIT $3 OFFSET $4;

-- name: CountVulnerabilitiesBySnapshotAndType :one
SELECT COUNT(*)::bigint FROM vulnerabilities
WHERE snapshot_id = $1 AND type = $2
  AND status = ANY(@statuses::vulnerability_status[]);

-- name: ListVulnerabilitySummaryBySnapshot :many
SELECT severity::text, COUNT(*)::bigint AS count
FROM vulnerabilities
WHERE snapshot_id = $1 AND status != 'resolved'
GROUP BY severity;

-- name: CountVulnerabilitiesBySeverity :many
SELECT severity::text, COUNT(*)::bigint AS count
FROM vulnerabilities
WHERE snapshot_id = $1 AND status != 'resolved'
GROUP BY severity;

-- name: CountVulnerabilitiesByType :many
SELECT type::text, COUNT(*)::bigint AS count
FROM vulnerabilities
WHERE snapshot_id = $1 AND status != 'resolved'
GROUP BY type;

-- name: UpdateVulnerabilityStatus :one
UPDATE vulnerabilities
SET status = $2,
    state_comment = $3,
    dismissal_reason = $4,
    confirmed_at = CASE WHEN $2 = 'confirmed' THEN NOW() ELSE confirmed_at END,
    confirmed_by = CASE WHEN $2 = 'confirmed' THEN $5 ELSE confirmed_by END,
    dismissed_at = CASE WHEN $2 = 'dismissed' THEN NOW() ELSE dismissed_at END,
    dismissed_by = CASE WHEN $2 = 'dismissed' THEN $5 ELSE dismissed_by END,
    resolved_at = CASE WHEN $2 = 'resolved' THEN NOW() ELSE resolved_at END,
    resolved_by = CASE WHEN $2 = 'resolved' THEN $5 ELSE resolved_by END,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: MarkStaleVulnerabilities :exec
UPDATE vulnerabilities SET status = 'resolved', resolved_at = NOW(), updated_at = NOW(), last_seen_at = NOW()
WHERE snapshot_id = sqlc.arg(snapshot_id)
  AND type = sqlc.arg(vuln_type)
  AND status NOT IN ('dismissed', 'resolved')
  AND id NOT IN (SELECT unnest(sqlc.arg(fresh_ids)::uuid[]));

-- name: CreateStateTransition :one
INSERT INTO vulnerability_state_transitions (vulnerability_id, state, changed_by, comment)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListStateTransitions :many
SELECT * FROM vulnerability_state_transitions
WHERE vulnerability_id = $1
ORDER BY changed_at DESC;

-- name: CreateExternalIssue :one
INSERT INTO vulnerability_external_issues (vulnerability_id, tracker_type, external_id, url)
VALUES ($1, $2, $3, $4)
ON CONFLICT (vulnerability_id, tracker_type, external_id) DO UPDATE SET url = EXCLUDED.url
RETURNING *;

-- name: ListExternalIssues :many
SELECT * FROM vulnerability_external_issues WHERE vulnerability_id = $1;

-- name: DeleteExternalIssue :exec
DELETE FROM vulnerability_external_issues WHERE id = $1;

-- name: CountVulnerabilitiesByOrg :one
SELECT COUNT(*)::bigint
FROM vulnerabilities v
WHERE v.org_id = $1 AND v.status NOT IN ('resolved', 'dismissed');

-- name: SearchVulnerabilities :many
SELECT v.*
FROM vulnerabilities v
WHERE v.org_id = $1
  AND (v.title ILIKE $2 ESCAPE '\\' OR v.description ILIKE $2 ESCAPE '\\' OR v.primary_identifier_value ILIKE $2 ESCAPE '\\')
ORDER BY v.detected_at DESC LIMIT $3 OFFSET $4;

-- name: CountSearchVulnerabilities :one
SELECT COUNT(*)::bigint
FROM vulnerabilities v
WHERE v.org_id = $1
  AND (v.title ILIKE $2 ESCAPE '\\' OR v.description ILIKE $2 ESCAPE '\\' OR v.primary_identifier_value ILIKE $2 ESCAPE '\\');

-- name: ListVulnerabilityToolStats :many
SELECT scanner_name, type::text, COUNT(*)::bigint AS count
FROM vulnerabilities
WHERE org_id = $1 AND status != 'resolved'
GROUP BY scanner_name, type
ORDER BY count DESC;
