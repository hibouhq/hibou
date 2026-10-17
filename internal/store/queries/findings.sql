-- Findings once per repository, presence per snapshot (ADR-049). The
-- `vulnerabilities` view keeps every reader; these are the writers.

-- name: CreateVulnerability :one
-- One finding per (repository, type, fingerprint) and the snapshot's row
-- for it, in one statement. What a scan may refresh on the finding
-- follows ADR-049 §6: the rating on every scan unless a person overrode
-- it; the descriptive text, the latest location, the metadata and the
-- rule reference only from the default branch, so two branches on
-- different scanner versions cannot rewrite each other; the finding's
-- status never, since it is a person's decision. The snapshot row takes
-- what the producer reported for this occurrence (its status, the
-- rating as scanned: original_severity, the CVSS score, the confidence),
-- and the location and metadata only where they differ from the
-- finding's latest. A row carried forward earlier in
-- this snapshot becomes a real observation; a row the scan had stopped
-- matching is matched again.
WITH snap AS (
    SELECT s.id, s.org_id, s.repo_id,
           (r.name = repo.default_branch OR r.name = 'refs/heads/' || repo.default_branch) AS is_default
    FROM snapshots s
    JOIN refs r ON r.id = s.ref_id
    JOIN repositories repo ON repo.id = s.repo_id
    WHERE s.id = sqlc.arg(snapshot_id)::uuid
), f AS (
    INSERT INTO findings (
        org_id, repo_id, type, fingerprint, title, description, primary_identifier_kind, primary_identifier_value,
        severity, cvss_version, cvss_vector, rated_by,
        scanner_name, scanner_vendor, scanner_version, scanner_external_id,
        file_path, start_line, end_line, location_hash,
        component_id, component_name, component_version, component_purl, ecosystem, advisory_id, affected_range_id,
        language, solution, has_remediation, remediation_link,
        secret_type, secret_hash, commit_sha, author_email, verified,
        created_by, metadata, rule_ref_id,
        origin, origin_api_key_id, origin_token_name, origin_owner_type, origin_owner_id
    )
    SELECT snap.org_id, snap.repo_id, sqlc.arg(type)::vulnerability_type, sqlc.arg(fingerprint)::text,
        sqlc.arg(title)::text, sqlc.arg(description)::text, sqlc.arg(primary_identifier_kind)::text, sqlc.arg(primary_identifier_value)::text,
        sqlc.arg(severity)::severity_level, sqlc.narg(cvss_version)::cvss_version, sqlc.arg(cvss_vector)::text, sqlc.arg(rated_by)::text,
        sqlc.arg(scanner_name)::text, sqlc.arg(scanner_vendor)::text, sqlc.arg(scanner_version)::text, sqlc.arg(scanner_external_id)::text,
        sqlc.narg(file_path)::text, sqlc.narg(start_line)::integer, sqlc.narg(end_line)::integer, sqlc.narg(location_hash)::text,
        sqlc.narg(component_id)::uuid, sqlc.narg(component_name)::text, sqlc.narg(component_version)::text, sqlc.narg(component_purl)::text, sqlc.narg(ecosystem)::text,
        sqlc.narg(advisory_id)::uuid, sqlc.narg(affected_range_id)::uuid,
        sqlc.narg(language)::text, sqlc.narg(solution)::text, sqlc.arg(has_remediation)::boolean, sqlc.narg(remediation_link)::text,
        sqlc.narg(secret_type)::text, sqlc.narg(secret_hash)::text, sqlc.narg(commit_sha)::text, sqlc.narg(author_email)::text, sqlc.narg(verified)::boolean,
        sqlc.narg(created_by)::uuid, sqlc.arg(metadata)::jsonb, sqlc.narg(rule_ref_id)::uuid,
        sqlc.arg(origin)::finding_origin, sqlc.narg(origin_api_key_id)::uuid, sqlc.arg(origin_token_name)::text, sqlc.arg(origin_owner_type)::text, sqlc.narg(origin_owner_id)::uuid
    FROM snap
    ON CONFLICT (repo_id, type, fingerprint) DO UPDATE SET
        severity = CASE WHEN findings.severity_override_by IS NULL THEN EXCLUDED.severity ELSE findings.severity END,
        cvss_version = EXCLUDED.cvss_version,
        cvss_vector = EXCLUDED.cvss_vector,
        rated_by = EXCLUDED.rated_by,
        title = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.title ELSE findings.title END,
        description = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.description ELSE findings.description END,
        solution = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.solution ELSE findings.solution END,
        has_remediation = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.has_remediation ELSE findings.has_remediation END,
        remediation_link = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.remediation_link ELSE findings.remediation_link END,
        language = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.language ELSE findings.language END,
        secret_type = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.secret_type ELSE findings.secret_type END,
        scanner_vendor = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.scanner_vendor ELSE findings.scanner_vendor END,
        scanner_version = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.scanner_version ELSE findings.scanner_version END,
        scanner_external_id = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.scanner_external_id ELSE findings.scanner_external_id END,
        file_path = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.file_path ELSE findings.file_path END,
        start_line = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.start_line ELSE findings.start_line END,
        end_line = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.end_line ELSE findings.end_line END,
        location_hash = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.location_hash ELSE findings.location_hash END,
        metadata = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.metadata ELSE findings.metadata END,
        rule_ref_id = CASE WHEN (SELECT is_default FROM snap) THEN EXCLUDED.rule_ref_id ELSE findings.rule_ref_id END,
        verified = CASE WHEN EXCLUDED.verified THEN true ELSE findings.verified END,
        last_seen_at = now(),
        updated_at = now()
    RETURNING id, file_path, start_line, end_line, location_hash, metadata
)
INSERT INTO snapshot_findings (
    snapshot_id, finding_id, severity, cvss_score, confidence, reachability, scan_status,
    file_path, start_line, end_line, location_hash, metadata
)
SELECT sqlc.arg(snapshot_id)::uuid, f.id, sqlc.arg(original_severity)::severity_level, sqlc.narg(cvss_score)::numeric,
       sqlc.narg(confidence)::text, sqlc.narg(reachability)::reachability, sqlc.arg(status)::vulnerability_status,
       CASE WHEN sqlc.narg(file_path)::text IS DISTINCT FROM f.file_path THEN sqlc.narg(file_path)::text END,
       CASE WHEN sqlc.narg(start_line)::integer IS DISTINCT FROM f.start_line THEN sqlc.narg(start_line)::integer END,
       CASE WHEN sqlc.narg(end_line)::integer IS DISTINCT FROM f.end_line THEN sqlc.narg(end_line)::integer END,
       CASE WHEN sqlc.narg(location_hash)::text IS DISTINCT FROM f.location_hash THEN sqlc.narg(location_hash)::text END,
       CASE WHEN sqlc.arg(metadata)::jsonb <> f.metadata THEN sqlc.arg(metadata)::jsonb ELSE '{}'::jsonb END
FROM f
ON CONFLICT (snapshot_id, finding_id) DO UPDATE SET
    severity = EXCLUDED.severity,
    cvss_score = EXCLUDED.cvss_score,
    confidence = EXCLUDED.confidence,
    reachability = COALESCE(EXCLUDED.reachability, snapshot_findings.reachability),
    scan_status = EXCLUDED.scan_status,
    file_path = EXCLUDED.file_path,
    start_line = EXCLUDED.start_line,
    end_line = EXCLUDED.end_line,
    location_hash = EXCLUDED.location_hash,
    metadata = EXCLUDED.metadata,
    resolved_at = NULL,
    presence = 'reported',
    presence_reason = NULL,
    last_seen_snapshot_id = NULL,
    consecutive_absences = 0
RETURNING finding_id;

-- name: GetVulnerabilityBySnapshotAndID :one
SELECT * FROM vulnerabilities WHERE snapshot_id = $1 AND id = $2;

-- name: GetVulnerabilityByID :one
-- A finding's id is stable across snapshots: the row returned is its
-- newest occurrence.
SELECT * FROM vulnerabilities WHERE id = $1 ORDER BY detected_at DESC LIMIT 1;

-- name: UpdateVulnerabilityStatus :one
-- Triage state lives on the finding, for every snapshot that carries it.
UPDATE findings
SET status = sqlc.arg(status)::vulnerability_status,
    state_comment = sqlc.arg(state_comment),
    resolved_at = CASE WHEN sqlc.arg(status)::vulnerability_status = 'resolved' THEN NOW() ELSE resolved_at END,
    resolved_by = CASE WHEN sqlc.arg(status)::vulnerability_status = 'resolved' THEN sqlc.arg(resolved_by) ELSE resolved_by END,
    updated_at = NOW()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: MarkStaleVulnerabilities :many
-- The scan no longer matches these on this snapshot: resolved here, the
-- finding's own state untouched. Returns the identifiers so the
-- notification dedup ledger can forget them.
UPDATE snapshot_findings sf
SET resolved_at = NOW()
FROM findings f
WHERE sf.snapshot_id = sqlc.arg(snapshot_id)
  AND f.id = sf.finding_id
  AND f.type = sqlc.arg(vuln_type)
  AND sf.resolved_at IS NULL
  AND f.status <> 'resolved'
  AND sf.finding_id NOT IN (SELECT unnest(sqlc.arg(fresh_ids)::uuid[]))
RETURNING f.primary_identifier_value;

-- name: SetVulnerabilityReachability :execrows
-- CI-side reachability analysis (govulncheck): match on the human identifier
-- or any advisory alias — analyzers speak GO-/CVE-/GHSA- interchangeably.
UPDATE snapshot_findings sf
SET reachability = sqlc.arg(reachability)
FROM findings f
WHERE sf.snapshot_id = $1
  AND f.id = sf.finding_id
  AND f.type IN ('dependency', 'malware')
  AND (
    f.primary_identifier_value = ANY(sqlc.arg(identifiers)::text[])
    OR EXISTS (
      SELECT 1 FROM advisories a
      WHERE a.id = f.advisory_id AND a.canonical_id = ANY(sqlc.arg(identifiers)::text[])
    )
    OR EXISTS (
      SELECT 1 FROM advisory_aliases aa
      WHERE aa.advisory_id = f.advisory_id AND aa.alias = ANY(sqlc.arg(identifiers)::text[])
    )
  );

-- name: SetVulnerabilityReachabilityByIDs :execrows
UPDATE snapshot_findings
SET reachability = sqlc.arg(reachability)
WHERE snapshot_id = sqlc.arg(snapshot_id) AND finding_id = ANY(sqlc.arg(ids)::uuid[]);

-- name: CopyMatchedVulnerabilities :many
-- The dependency and malware matches of one snapshot, carried to another
-- with the same inventory (scan reuse, ADR-045): the pointer rows, not
-- the findings. Rows the prior scan stopped matching or only carried
-- forward are not matches and stay behind.
INSERT INTO snapshot_findings (
    snapshot_id, finding_id, severity, cvss_score, confidence, scan_status,
    file_path, start_line, end_line, location_hash, metadata
)
SELECT sqlc.arg(to_snapshot_id)::uuid, src.finding_id, src.severity, src.cvss_score, src.confidence, src.scan_status,
       src.file_path, src.start_line, src.end_line, src.location_hash, src.metadata
FROM snapshot_findings src
JOIN findings f ON f.id = src.finding_id
WHERE src.snapshot_id = sqlc.arg(from_snapshot_id)::uuid
  AND f.type IN ('dependency', 'malware')
  AND src.resolved_at IS NULL
  AND src.scan_status <> 'resolved'
  AND src.presence = 'reported'
ON CONFLICT (snapshot_id, finding_id) DO UPDATE SET
    resolved_at = NULL, presence = 'reported', presence_reason = NULL, last_seen_snapshot_id = NULL, consecutive_absences = 0
RETURNING finding_id, severity,
    (SELECT f.type::text FROM findings f WHERE f.id = snapshot_findings.finding_id) AS type,
    (SELECT f.primary_identifier_value FROM findings f WHERE f.id = snapshot_findings.finding_id) AS primary_identifier_value,
    (SELECT f.component_name FROM findings f WHERE f.id = snapshot_findings.finding_id) AS component_name,
    (SELECT f.component_version FROM findings f WHERE f.id = snapshot_findings.finding_id) AS component_version;

-- name: DeleteVulnerabilitiesBySnapshot :exec
-- Retention's rollup: the snapshot's rows go, the findings stay for the
-- snapshots that still carry them and for the collector.
DELETE FROM snapshot_findings WHERE snapshot_id = $1;

-- name: CollectOrphanFindings :execrows
-- Findings no snapshot carries any more, once nothing has seen them for
-- a month: their history goes with them, acceptances by fingerprint stay.
DELETE FROM findings f
WHERE f.id IN (
    SELECT f2.id FROM findings f2
    WHERE f2.last_seen_at < now() - interval '30 days'
      AND NOT EXISTS (SELECT 1 FROM snapshot_findings sf WHERE sf.finding_id = f2.id)
    LIMIT $1
);

-- name: GetFindingByID :one
SELECT * FROM findings WHERE id = $1;

-- name: FindingStats :one
SELECT (SELECT count(*) FROM findings)::bigint AS findings,
       (SELECT count(*) FROM snapshot_findings)::bigint AS snapshot_rows;
