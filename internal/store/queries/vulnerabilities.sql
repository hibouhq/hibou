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
    rule_ref_id,
    origin,
    origin_api_key_id,
    origin_token_name,
    origin_owner_type,
    origin_owner_id
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
    $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
    $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
    $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
    $41, $42, $43, $44
)
ON CONFLICT (snapshot_id, type, fingerprint) DO UPDATE SET
    last_seen_at = NOW(),
    severity = EXCLUDED.severity,
    original_severity = EXCLUDED.original_severity,
    status = CASE WHEN vulnerabilities.status = 'resolved' THEN vulnerabilities.status ELSE EXCLUDED.status END,
    metadata = EXCLUDED.metadata,
    rule_ref_id = EXCLUDED.rule_ref_id
RETURNING *;

-- name: GetVulnerabilityByID :one
SELECT * FROM vulnerabilities WHERE id = $1;

-- name: ListVulnerabilitiesBySnapshot :many
-- The acceptance LEFT JOIN is the ADR-023 hot read: decision status is
-- computed server-side off the (repo_id, fingerprint) unique index,
-- O(page size) lookups, never a client-side join.
SELECT sqlc.embed(v),
  fa.reason_kind AS acceptance_reason_kind,
  fa.reason AS acceptance_reason,
  fa.labels AS acceptance_labels,
  fa.vex_justification AS acceptance_vex_justification,
  fa.accepted_by AS acceptance_accepted_by,
  fa.expires_at AS acceptance_expires_at,
  fa.created_at AS acceptance_created_at
FROM vulnerabilities v
LEFT JOIN finding_acceptances fa
  ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
  AND (fa.expires_at IS NULL OR fa.expires_at > now())
WHERE v.snapshot_id = $1
  AND v.status = ANY(@statuses::vulnerability_status[])
  AND (COALESCE(array_length(@types::text[], 1), 0) = 0 OR v.type::text = ANY(@types::text[]))
  AND (COALESCE(array_length(@severities::text[], 1), 0) = 0 OR v.severity::text = ANY(@severities::text[]))
  AND (COALESCE(array_length(@scanners::text[], 1), 0) = 0 OR v.scanner_name = ANY(@scanners::text[]))
  AND (COALESCE(array_length(@languages::text[], 1), 0) = 0 OR COALESCE(v.language, '') = ANY(@languages::text[]))
  AND (@file_query::text = '' OR COALESCE(v.file_path, '') ILIKE '%' || @file_query::text || '%' ESCAPE '\')
  AND (@search::text = '' OR (v.title ILIKE '%' || @search::text || '%' ESCAPE '\' OR v.primary_identifier_value ILIKE '%' || @search::text || '%' ESCAPE '\'))
  AND (@acceptance::text = ''
       OR (@acceptance::text = 'open' AND fa.fingerprint IS NULL)
       OR (@acceptance::text = 'accepted' AND fa.fingerprint IS NOT NULL)
       OR fa.reason_kind::text = @acceptance::text)
ORDER BY
  CASE WHEN @sort::text = 'severity_asc' THEN v.severity_rank END ASC,
  CASE WHEN @sort::text = 'severity_desc' THEN v.severity_rank END DESC,
  CASE WHEN @sort::text = 'status_asc' THEN v.status END ASC,
  CASE WHEN @sort::text = 'status_desc' THEN v.status END DESC,
  CASE WHEN @sort::text = 'detected_asc' THEN v.detected_at END ASC,
  CASE WHEN @sort::text = 'detected_desc' OR @sort::text = '' THEN v.detected_at END DESC,
  v.id DESC
LIMIT $2 OFFSET $3;

-- name: CountVulnerabilitiesBySnapshot :one
SELECT COUNT(*)::bigint FROM vulnerabilities v
LEFT JOIN finding_acceptances fa
  ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
  AND (fa.expires_at IS NULL OR fa.expires_at > now())
WHERE v.snapshot_id = $1
  AND v.status = ANY(@statuses::vulnerability_status[])
  AND (COALESCE(array_length(@types::text[], 1), 0) = 0 OR v.type::text = ANY(@types::text[]))
  AND (COALESCE(array_length(@severities::text[], 1), 0) = 0 OR v.severity::text = ANY(@severities::text[]))
  AND (COALESCE(array_length(@scanners::text[], 1), 0) = 0 OR v.scanner_name = ANY(@scanners::text[]))
  AND (COALESCE(array_length(@languages::text[], 1), 0) = 0 OR COALESCE(v.language, '') = ANY(@languages::text[]))
  AND (@file_query::text = '' OR COALESCE(v.file_path, '') ILIKE '%' || @file_query::text || '%' ESCAPE '\')
  AND (@search::text = '' OR (v.title ILIKE '%' || @search::text || '%' ESCAPE '\' OR v.primary_identifier_value ILIKE '%' || @search::text || '%' ESCAPE '\'))
  AND (@acceptance::text = ''
       OR (@acceptance::text = 'open' AND fa.fingerprint IS NULL)
       OR (@acceptance::text = 'accepted' AND fa.fingerprint IS NOT NULL)
       OR fa.reason_kind::text = @acceptance::text);

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
    resolved_at = CASE WHEN $2 = 'resolved' THEN NOW() ELSE resolved_at END,
    resolved_by = CASE WHEN $2 = 'resolved' THEN $4 ELSE resolved_by END,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: MarkStaleVulnerabilities :exec
UPDATE vulnerabilities SET status = 'resolved', resolved_at = NOW(), updated_at = NOW(), last_seen_at = NOW()
WHERE snapshot_id = sqlc.arg(snapshot_id)
  AND type = sqlc.arg(vuln_type)
  AND status != 'resolved'
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
-- ADR-023 risk semantics: a false positive never was a vulnerability.
SELECT COUNT(*)::bigint
FROM vulnerabilities v
WHERE v.org_id = $1 AND v.status NOT IN ('resolved', 'suppressed')
  AND NOT EXISTS (
    SELECT 1 FROM finding_acceptances fa
    WHERE fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
      AND fa.reason_kind = 'false_positive'
      AND (fa.expires_at IS NULL OR fa.expires_at > now())
  );

-- name: SearchVulnerabilities :many
SELECT v.*
FROM vulnerabilities v
WHERE v.org_id = $1
  AND (v.title ILIKE $2 ESCAPE '\' OR v.description ILIKE $2 ESCAPE '\' OR v.primary_identifier_value ILIKE $2 ESCAPE '\')
ORDER BY v.detected_at DESC LIMIT $3 OFFSET $4;

-- name: CountSearchVulnerabilities :one
SELECT COUNT(*)::bigint
FROM vulnerabilities v
WHERE v.org_id = $1
  AND (v.title ILIKE $2 ESCAPE '\' OR v.description ILIKE $2 ESCAPE '\' OR v.primary_identifier_value ILIKE $2 ESCAPE '\');

-- name: ListVulnerabilityToolStats :many
SELECT scanner_name, type::text, COUNT(*)::bigint AS count
FROM vulnerabilities
WHERE org_id = $1 AND status != 'resolved'
GROUP BY scanner_name, type
ORDER BY count DESC;

-- name: UpsertFindingAcceptance :one
INSERT INTO finding_acceptances (repo_id, fingerprint, reason_kind, reason, labels, vex_justification, accepted_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (repo_id, fingerprint) DO UPDATE SET
	reason_kind = EXCLUDED.reason_kind,
	reason = EXCLUDED.reason,
	labels = EXCLUDED.labels,
	vex_justification = EXCLUDED.vex_justification,
	accepted_by = EXCLUDED.accepted_by,
	expires_at = EXCLUDED.expires_at,
	created_at = now()
RETURNING *;

-- name: DeleteFindingAcceptance :execrows
DELETE FROM finding_acceptances WHERE repo_id = $1 AND fingerprint = $2;

-- name: ListActiveFindingAcceptancesByRepo :many
SELECT * FROM finding_acceptances
WHERE repo_id = $1 AND (expires_at IS NULL OR expires_at > now());

-- name: ListRepoFingerprints :many
-- Returns the subset of the given fingerprints that actually belongs to this
-- repository. Batch triage validates against this so a caller cannot write
-- acceptances for another repo's findings by guessing fingerprints.
SELECT DISTINCT v.fingerprint
FROM vulnerabilities v
JOIN snapshots s ON s.id = v.snapshot_id
JOIN refs rf ON rf.id = s.ref_id
WHERE rf.repo_id = $1
  AND v.fingerprint = ANY($2::text[]);

-- name: ListAcceptedDependencyAdvisories :many
-- Acceptance decisions on component-backed findings, joined to their advisory
-- for VEX synthesis at export time (ADR-023: acceptances GENERATE VEX; no
-- materialized rows to drift).
SELECT DISTINCT fa.fingerprint, fa.reason_kind, fa.reason, fa.vex_justification, fa.expires_at,
  v.advisory_id, a.canonical_id, v.component_purl
FROM finding_acceptances fa
JOIN vulnerabilities v ON v.repo_id = fa.repo_id AND v.fingerprint = fa.fingerprint
JOIN advisories a ON a.id = v.advisory_id
WHERE fa.repo_id = $1 AND (fa.expires_at IS NULL OR fa.expires_at > now())
  AND v.advisory_id IS NOT NULL AND v.type IN ('dependency', 'container');
