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
  fa.created_at AS acceptance_created_at,
  fd.reason AS dispute_reason,
  fd.created_at AS dispute_created_at
FROM vulnerabilities v
LEFT JOIN finding_acceptances fa
  ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
  AND (fa.expires_at IS NULL OR fa.expires_at > now())
LEFT JOIN finding_disputes fd
  ON fd.repo_id = v.repo_id AND fd.fingerprint = v.fingerprint
WHERE v.snapshot_id = $1
  AND v.status = ANY(@statuses::vulnerability_status[])
  AND (COALESCE(array_length(@types::text[], 1), 0) = 0 OR v.type::text = ANY(@types::text[]))
  AND (COALESCE(array_length(@severities::text[], 1), 0) = 0 OR v.severity::text = ANY(@severities::text[]))
  AND (COALESCE(array_length(@scanners::text[], 1), 0) = 0 OR v.scanner_name = ANY(@scanners::text[]))
  AND (COALESCE(array_length(@languages::text[], 1), 0) = 0 OR COALESCE(v.language, '') = ANY(@languages::text[]))
  AND (@file_query::text = '' OR COALESCE(v.file_path, '') ILIKE '%' || @file_query::text || '%' ESCAPE '\')
  AND (@search::text = '' OR (v.title ILIKE '%' || @search::text || '%' ESCAPE '\' OR v.primary_identifier_value ILIKE '%' || @search::text || '%' ESCAPE '\'))
  AND (@shipped::text = ''
       OR (@shipped::text = 'no' AND COALESCE(v.component_id = ANY(@not_shipped_component_ids::uuid[]), false))
       OR (@shipped::text = 'yes' AND NOT COALESCE(v.component_id = ANY(@not_shipped_component_ids::uuid[]), false)))
  AND (@acceptance::text = ''
       OR (@acceptance::text = 'open' AND fa.fingerprint IS NULL)
       OR (@acceptance::text = 'accepted' AND fa.fingerprint IS NOT NULL)
       OR (@acceptance::text = 'disputed' AND fd.fingerprint IS NOT NULL)
       OR fa.reason_kind::text = @acceptance::text)
  AND (@exploited::text = ''
       OR (@exploited::text = 'true' AND v.type::text IN ('dependency','container','malware') AND (
         EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))
         OR EXISTS (SELECT 1 FROM advisories adv
                    LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id
                    JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))
                    WHERE adv.id = v.advisory_id)))
       OR (@exploited::text = 'false' AND NOT (v.type::text IN ('dependency','container','malware') AND (
         EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))
         OR EXISTS (SELECT 1 FROM advisories adv
                    LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id
                    JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))
                    WHERE adv.id = v.advisory_id)))))
  AND (NOT @risk_only::bool OR (
       v.status != 'resolved'
         AND (v.status != 'suppressed' OR fd.fingerprint IS NOT NULL)
         AND COALESCE(fa.reason_kind::text, '') != 'false_positive'))
ORDER BY
  -- Open malware first, whatever the sort: a malicious package must be the
  -- first row anyone sees. "Open" is openMalwareCount's definition: detected,
  -- or suppressed with a dispute; a false-positive acceptance clears it.
  CASE WHEN v.type = 'malware'
        AND (v.status = 'detected' OR (v.status = 'suppressed' AND fd.fingerprint IS NOT NULL))
        AND COALESCE(fa.reason_kind::text, '') <> 'false_positive'
    THEN 0 ELSE 1 END ASC,
  CASE WHEN @sort::text IN ('', 'detected_desc', 'severity_desc', 'risk_desc')
       AND v.type::text IN ('dependency', 'container', 'malware') AND (
         EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))
         OR EXISTS (SELECT 1 FROM advisories adv
                    LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id
                    JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))
                    WHERE adv.id = v.advisory_id))
    THEN 0 ELSE 1 END ASC,
  -- ADR-038 §5: Risk is KEV (above), then EPSS, then CVSS; unscored last.
  CASE WHEN @sort::text IN ('risk_desc', 'epss_desc') THEN GREATEST((SELECT e.score FROM epss_scores e WHERE e.cve_id = upper(v.primary_identifier_value)), (SELECT max(e.score) FROM advisory_aliases al JOIN epss_scores e ON e.cve_id = upper(al.alias) WHERE al.advisory_id = v.advisory_id)) END DESC NULLS LAST,
  CASE WHEN @sort::text IN ('risk_desc', 'cvss_desc') THEN v.cvss_score END DESC NULLS LAST,
  CASE WHEN @sort::text = 'risk_desc' THEN v.severity_rank END DESC,
  CASE WHEN @sort::text IN ('risk_asc', 'epss_asc') THEN GREATEST((SELECT e.score FROM epss_scores e WHERE e.cve_id = upper(v.primary_identifier_value)), (SELECT max(e.score) FROM advisory_aliases al JOIN epss_scores e ON e.cve_id = upper(al.alias) WHERE al.advisory_id = v.advisory_id)) END ASC NULLS FIRST,
  CASE WHEN @sort::text IN ('risk_asc', 'cvss_asc') THEN v.cvss_score END ASC NULLS FIRST,
  CASE WHEN @sort::text = 'risk_asc' THEN v.severity_rank END ASC,
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
LEFT JOIN finding_disputes fd
  ON fd.repo_id = v.repo_id AND fd.fingerprint = v.fingerprint
WHERE v.snapshot_id = $1
  AND v.status = ANY(@statuses::vulnerability_status[])
  AND (COALESCE(array_length(@types::text[], 1), 0) = 0 OR v.type::text = ANY(@types::text[]))
  AND (COALESCE(array_length(@severities::text[], 1), 0) = 0 OR v.severity::text = ANY(@severities::text[]))
  AND (COALESCE(array_length(@scanners::text[], 1), 0) = 0 OR v.scanner_name = ANY(@scanners::text[]))
  AND (COALESCE(array_length(@languages::text[], 1), 0) = 0 OR COALESCE(v.language, '') = ANY(@languages::text[]))
  AND (@file_query::text = '' OR COALESCE(v.file_path, '') ILIKE '%' || @file_query::text || '%' ESCAPE '\')
  AND (@search::text = '' OR (v.title ILIKE '%' || @search::text || '%' ESCAPE '\' OR v.primary_identifier_value ILIKE '%' || @search::text || '%' ESCAPE '\'))
  AND (@shipped::text = ''
       OR (@shipped::text = 'no' AND COALESCE(v.component_id = ANY(@not_shipped_component_ids::uuid[]), false))
       OR (@shipped::text = 'yes' AND NOT COALESCE(v.component_id = ANY(@not_shipped_component_ids::uuid[]), false)))
  AND (@acceptance::text = ''
       OR (@acceptance::text = 'open' AND fa.fingerprint IS NULL)
       OR (@acceptance::text = 'accepted' AND fa.fingerprint IS NOT NULL)
       OR (@acceptance::text = 'disputed' AND fd.fingerprint IS NOT NULL)
       OR fa.reason_kind::text = @acceptance::text)
  AND (@exploited::text = ''
       OR (@exploited::text = 'true' AND v.type::text IN ('dependency','container','malware') AND (
         EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))
         OR EXISTS (SELECT 1 FROM advisories adv
                    LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id
                    JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))
                    WHERE adv.id = v.advisory_id)))
       OR (@exploited::text = 'false' AND NOT (v.type::text IN ('dependency','container','malware') AND (
         EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))
         OR EXISTS (SELECT 1 FROM advisories adv
                    LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id
                    JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))
                    WHERE adv.id = v.advisory_id)))))
  AND (NOT @risk_only::bool OR (
       v.status != 'resolved'
         AND (v.status != 'suppressed' OR fd.fingerprint IS NOT NULL)
         AND COALESCE(fa.reason_kind::text, '') != 'false_positive'));

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

-- name: GetLatestVulnerabilityByFingerprint :one
-- The newest occurrence of a fingerprint on a repo — the finding-detail
-- drawer's anchor row.
SELECT * FROM vulnerabilities
WHERE repo_id = $1 AND fingerprint = $2
ORDER BY detected_at DESC
LIMIT 1;

-- name: ListFindingOccurrences :many
-- Where a fingerprint is currently detected: each ref's latest usable
-- snapshot, joined to the finding. Answers "is this everywhere or just on
-- one branch" in one indexed pass per ref.
SELECT r.name AS ref_name, r.ref_type::text AS ref_type, s.commit_sha, s.created_at AS snapshot_at, v.status::text AS status
FROM refs r
JOIN LATERAL (
    SELECT s.id, s.commit_sha, s.created_at
    FROM snapshots s
    WHERE s.ref_id = r.id AND s.status IN ('complete', 'active')
    ORDER BY s.created_at DESC
    LIMIT 1
) s ON TRUE
JOIN vulnerabilities v ON v.snapshot_id = s.id AND v.fingerprint = sqlc.arg(fingerprint)
WHERE r.repo_id = $1
ORDER BY s.created_at DESC;

-- name: GetActiveFindingAcceptance :one
SELECT * FROM finding_acceptances
WHERE repo_id = $1 AND fingerprint = $2
  AND (expires_at IS NULL OR expires_at > now());

-- name: ListDependencyFindingHeadsBySnapshot :many
-- The reachability classification's working set: dependency/container rows
-- only, and only the columns the classifier reads. On a large monorepo this
-- is thousands of rows instead of the snapshot's tens of thousands, and it
-- runs on EVERY build's reachability post — the projection matters.
SELECT id, ecosystem, component_name, advisory_id, reachability
FROM vulnerabilities
WHERE snapshot_id = $1 AND type IN ('dependency', 'container');

-- name: ListUnreachableDependencyAdvisories :many
-- Machine-proven not_reachable dependency findings on one snapshot — the
-- source for synthesized VEX not_affected/vulnerable_code_not_in_execute_path
-- statements. Human statements and acceptances take precedence at export.
SELECT DISTINCT a.canonical_id, v.advisory_id, v.component_purl
FROM vulnerabilities v
JOIN advisories a ON a.id = v.advisory_id
WHERE v.snapshot_id = $1
  AND v.type IN ('dependency', 'container')
  AND v.reachability = 'not_reachable'
  AND v.advisory_id IS NOT NULL;

-- name: ListFindingTransitions :many
-- The scan-observed life of a fingerprint, per ref: the snapshot that first
-- reported it and every later snapshot whose status differs from the previous
-- one. The snapshot series already is the history, so the timeline needs no
-- separate event table — only the rows where something actually changed.
WITH observations AS (
    SELECT r.id AS ref_id,
           r.name AS ref_name,
           r.ref_type::text AS ref_type,
           s.commit_sha,
           s.created_at AS observed_at,
           v.status::text AS status,
           v.severity::text AS severity,
           v.reachability::text AS reachability,
           -- The in-source suppression justification the scanner extracted
           -- (e.g. the text after `#nosec G115 --`), carried on the row's
           -- metadata by the ingest. Shown as the comment of the transition
           -- that suppressed the finding.
           v.metadata #>> '{suppression,justification}' AS suppression_justification,
           LAG(v.status::text) OVER (PARTITION BY r.id ORDER BY s.created_at, s.id) AS previous_status,
           LAG(v.reachability::text) OVER (PARTITION BY r.id ORDER BY s.created_at, s.id) AS previous_reachability,
           -- ADR-034: a carried row (not re-checked) and its return to a real
           -- report are timeline events too.
           v.presence::text AS presence,
           v.presence_reason,
           LAG(v.presence::text) OVER (PARTITION BY r.id ORDER BY s.created_at, s.id) AS previous_presence
    FROM vulnerabilities v
    JOIN snapshots s ON s.id = v.snapshot_id
    JOIN refs r ON r.id = s.ref_id
    WHERE v.repo_id = $1
      AND v.fingerprint = $2
      AND s.status IN ('complete', 'active')
)
SELECT ref_name, ref_type, commit_sha, observed_at, status, severity,
       COALESCE(previous_status, '')::text AS previous_status,
       COALESCE(suppression_justification, '')::text AS suppression_justification,
       COALESCE(reachability, '')::text AS reachability,
       COALESCE(previous_reachability, '')::text AS previous_reachability,
       presence,
       COALESCE(previous_presence, '')::text AS previous_presence,
       COALESCE(presence_reason, '')::text AS presence_reason
FROM observations
WHERE previous_status IS DISTINCT FROM status
   OR (previous_presence IS NOT NULL AND previous_presence IS DISTINCT FROM presence)
   -- A reachability verdict is a timeline event too: it changes whether the
   -- finding gates (org opt-in) and what the VEX export says. Only definite
   -- verdicts qualify — a new snapshot's rows start unknown until classified,
   -- and "went back to unknown" would be noise, not information.
   OR (reachability IS DISTINCT FROM previous_reachability AND reachability IN ('reachable', 'not_reachable'))
ORDER BY observed_at DESC, ref_name
LIMIT sqlc.arg(row_limit);

-- name: GetFindingFirstObservation :one
-- The birth of a fingerprint on a repository: the oldest observation of it,
-- dated by first_seen_at (which the ingest carries forward across snapshots)
-- rather than by the snapshot that happens to be the oldest one still stored.
-- The timeline anchors on this, so "when did this appear" survives even when
-- the transition list is capped.
SELECT r.name AS ref_name,
       r.ref_type::text AS ref_type,
       s.commit_sha,
       LEAST(v.first_seen_at, s.created_at)::timestamptz AS observed_at,
       v.severity::text AS severity
FROM vulnerabilities v
JOIN snapshots s ON s.id = v.snapshot_id
JOIN refs r ON r.id = s.ref_id
WHERE v.repo_id = $1
  AND v.fingerprint = $2
  AND s.status IN ('complete', 'active')
ORDER BY LEAST(v.first_seen_at, s.created_at) ASC, s.created_at ASC
LIMIT 1;

