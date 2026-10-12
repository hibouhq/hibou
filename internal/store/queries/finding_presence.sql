-- name: LockRefForPresence :exec
-- Serializes carry-forward per ref (ADR-034, D2): two snapshots of one ref
-- finishing together must not plan against each other's half-written rows.
SELECT pg_advisory_xact_lock(hashtextextended('finding_presence:' || sqlc.arg(ref_id)::text, 0));

-- name: CarryVulnerabilitiesForward :execrows
-- Copies previous findings into a snapshot as carried rows. Every column of
-- the source row is kept except identity, tenancy (set by trigger) and the
-- presence fields given here. A row the producer reported meanwhile wins
-- (DO NOTHING on the snapshot's identity key).
INSERT INTO vulnerabilities (
    type, snapshot_id, title, description, original_severity, severity,
    severity_override_reason, severity_override_by, status, state_comment,
    detected_at, resolved_at, resolved_by, scanner_name, scanner_vendor,
    scanner_version, scanner_external_id, file_path, start_line, end_line,
    location_hash, fingerprint, component_id, component_name, component_version,
    component_purl, ecosystem, advisory_id, affected_range_id, language,
    confidence, solution, has_remediation, remediation_link, reachability,
    due_date, present_on_default_branch, resolved_on_default_branch, secret_type,
    secret_hash, commit_sha, author_email, verified, created_by, metadata,
    first_seen_at, last_seen_at, rule_ref_id, primary_identifier_kind,
    primary_identifier_value, origin, origin_api_key_id, origin_token_name,
    origin_owner_type, origin_owner_id, cvss_score, cvss_version, cvss_vector,
    rated_by, presence, presence_reason, last_seen_snapshot_id, last_seen_commit,
    consecutive_absences
)
SELECT
    v.type, sqlc.arg(snapshot_id)::uuid, v.title, v.description, v.original_severity, v.severity,
    v.severity_override_reason, v.severity_override_by, v.status, v.state_comment,
    v.detected_at, v.resolved_at, v.resolved_by, v.scanner_name, v.scanner_vendor,
    v.scanner_version, v.scanner_external_id, v.file_path, v.start_line, v.end_line,
    v.location_hash, v.fingerprint, v.component_id, v.component_name, v.component_version,
    v.component_purl, v.ecosystem, v.advisory_id, v.affected_range_id, v.language,
    v.confidence, v.solution, v.has_remediation, v.remediation_link, v.reachability,
    v.due_date, v.present_on_default_branch, v.resolved_on_default_branch, v.secret_type,
    v.secret_hash, v.commit_sha, v.author_email, v.verified, v.created_by, v.metadata,
    v.first_seen_at, v.last_seen_at, v.rule_ref_id, v.primary_identifier_kind,
    v.primary_identifier_value, v.origin, v.origin_api_key_id, v.origin_token_name,
    v.origin_owner_type, v.origin_owner_id, v.cvss_score, v.cvss_version, v.cvss_vector,
    v.rated_by, c.presence::finding_presence, c.reason, c.last_seen_snapshot_id, c.last_seen_commit,
    c.consecutive_absences
FROM jsonb_to_recordset(sqlc.arg(carries)::jsonb) AS c(
    id uuid, presence text, reason text, last_seen_snapshot_id uuid,
    last_seen_commit text, consecutive_absences int
)
JOIN vulnerabilities v ON v.id = c.id
ON CONFLICT (snapshot_id, type, fingerprint) DO NOTHING;

-- name: UpdateCarriedPresence :exec
UPDATE vulnerabilities
SET presence = sqlc.arg(presence)::finding_presence,
    presence_reason = sqlc.narg(reason),
    last_seen_snapshot_id = sqlc.narg(last_seen_snapshot_id),
    last_seen_commit = sqlc.narg(last_seen_commit),
    consecutive_absences = sqlc.arg(consecutive_absences),
    updated_at = now()
WHERE id = sqlc.arg(id) AND presence <> 'reported';

-- name: DeleteCarriedVulnerabilities :execrows
-- Only carried rows: a producer's own observation is never deleted here.
DELETE FROM vulnerabilities
WHERE id = ANY(sqlc.arg(ids)::uuid[]) AND presence <> 'reported';

-- name: DeleteFindingResolutionsBySnapshot :exec
-- Reconcile rewrites a snapshot's resolutions whole: a late producer can turn
-- a "fixed" into "not re-checked" or the reverse.
DELETE FROM finding_resolutions WHERE snapshot_id = $1;

-- name: InsertFindingResolutions :execrows
INSERT INTO finding_resolutions (repo_id, ref_id, snapshot_id, type, fingerprint, producer, reason, commit_sha)
SELECT rf.repo_id, s.ref_id, s.id, r.type, r.fingerprint, r.producer, r.reason, s.commit_sha
FROM jsonb_to_recordset(sqlc.arg(resolutions)::jsonb) AS r(type text, fingerprint text, producer text, reason text)
JOIN snapshots s ON s.id = sqlc.arg(snapshot_id)::uuid
JOIN refs rf ON rf.id = s.ref_id
ON CONFLICT (snapshot_id, type, fingerprint) DO UPDATE SET
    producer = EXCLUDED.producer,
    reason = EXCLUDED.reason;

-- name: ListFindingResolutions :many
-- Resolution events of a fingerprint on a repo, newest first, with the ref
-- name for the timeline.
SELECT fr.reason, fr.producer, fr.commit_sha, fr.created_at, rf.name AS ref_name, rf.ref_type::text AS ref_type,
       COALESCE((SELECT pr.version FROM producer_runs pr
                 WHERE pr.snapshot_id = fr.snapshot_id AND pr.producer = fr.producer AND pr.version IS NOT NULL
                 ORDER BY pr.created_at DESC LIMIT 1), '')::text AS producer_version
FROM finding_resolutions fr
JOIN refs rf ON rf.id = fr.ref_id
WHERE fr.repo_id = $1 AND fr.fingerprint = $2
ORDER BY fr.created_at DESC
LIMIT sqlc.arg(row_limit);

-- name: ListProducerPolicies :many
SELECT * FROM producer_policies WHERE org_id = $1 ORDER BY producer;

-- name: UpsertProducerPolicy :one
INSERT INTO producer_policies (org_id, producer, policy, threshold, updated_by, updated_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (org_id, producer) DO UPDATE SET
    policy = EXCLUDED.policy,
    threshold = EXCLUDED.threshold,
    updated_by = EXCLUDED.updated_by,
    updated_at = now()
RETURNING *;

-- name: DeleteProducerPolicy :execrows
DELETE FROM producer_policies WHERE org_id = $1 AND producer = $2;

-- name: ListPresenceRowsBySnapshot :many
-- The columns finding presence reads, nothing else: reconcile runs after
-- every producer, on snapshots that can hold tens of thousands of rows.
SELECT id, type::text AS type, fingerprint, scanner_name, file_path, status::text AS status,
       origin::text AS origin, presence::text AS presence, presence_reason,
       last_seen_snapshot_id, last_seen_commit, consecutive_absences,
       COALESCE(metadata -> 'trace_files', 'null'::jsonb) AS trace_files
FROM vulnerabilities
WHERE snapshot_id = $1;
