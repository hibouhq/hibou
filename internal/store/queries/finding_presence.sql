-- name: LockRefForPresence :exec
-- Serializes carry-forward per ref (ADR-034, D2): two snapshots of one ref
-- finishing together must not plan against each other's half-written rows.
SELECT pg_advisory_xact_lock(hashtextextended('finding_presence:' || sqlc.arg(ref_id)::text, 0));

-- name: CarryVulnerabilitiesForward :execrows
-- Copies the previous snapshot's rows into the snapshot as carried rows
-- (ADR-034): the pointer rows with their as-scanned values, the presence
-- fields given here. A row the producer reported meanwhile wins.
INSERT INTO snapshot_findings (
    snapshot_id, finding_id, detected_at, severity, cvss_score, confidence, reachability, scan_status, resolved_at,
    presence, presence_reason, last_seen_snapshot_id, consecutive_absences,
    file_path, start_line, end_line, location_hash, metadata
)
SELECT sqlc.arg(snapshot_id)::uuid, src.finding_id, src.detected_at, src.severity, src.cvss_score, src.confidence, src.reachability, src.scan_status, src.resolved_at,
       c.presence::finding_presence, c.reason, c.last_seen_snapshot_id, c.consecutive_absences,
       src.file_path, src.start_line, src.end_line, src.location_hash, src.metadata
FROM jsonb_to_recordset(sqlc.arg(carries)::jsonb) AS c(
    id uuid, presence text, reason text, last_seen_snapshot_id uuid, consecutive_absences int
)
JOIN snapshot_findings src ON src.finding_id = c.id AND src.snapshot_id = sqlc.arg(from_snapshot_id)::uuid
ON CONFLICT (snapshot_id, finding_id) DO NOTHING;

-- name: UpdateCarriedPresence :exec
UPDATE snapshot_findings
SET presence = sqlc.arg(presence)::finding_presence,
    presence_reason = sqlc.narg(reason),
    last_seen_snapshot_id = sqlc.narg(last_seen_snapshot_id),
    consecutive_absences = sqlc.arg(consecutive_absences)
WHERE snapshot_id = sqlc.arg(snapshot_id) AND finding_id = sqlc.arg(id) AND presence <> 'reported';

-- name: DeleteCarriedVulnerabilities :execrows
-- Only carried rows: a producer's own observation is never deleted here.
DELETE FROM snapshot_findings
WHERE snapshot_id = sqlc.arg(snapshot_id) AND finding_id = ANY(sqlc.arg(ids)::uuid[]) AND presence <> 'reported';

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
