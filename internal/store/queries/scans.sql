-- name: CreateScan :one
INSERT INTO scans (snapshot_id, status, providers_requested, triggered_by)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetScanByID :one
SELECT * FROM scans WHERE id = $1;

-- name: ListScansBySnapshot :many
SELECT * FROM scans WHERE snapshot_id = $1 ORDER BY created_at DESC;

-- name: UpdateScanStatus :one
UPDATE scans SET status = $2, error_message = $3, started_at = $4, completed_at = $5
WHERE id = $1 RETURNING *;

-- name: CreateScanProvider :one
INSERT INTO scan_providers (scan_id, provider, status)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateScanProvider :one
UPDATE scan_providers SET
    status = $2, cache_hits = $3, cache_misses = $4, advisories_found = $5,
    response_time_ms = $6, db_version = $7, error_message = $8,
    started_at = $9, completed_at = $10
WHERE id = $1 RETURNING *;

-- name: ListScanProvidersByScan :many
SELECT * FROM scan_providers WHERE scan_id = $1;
-- name: GetGateScanReadiness :one
-- The gate's precondition (PLAN §1): a snapshot with components is gate-ready
-- only once an advisory scan has COMPLETED for it — a verdict computed between
-- artifact processing and the scan sees no dependency findings, reports them
-- all "resolved", and cannot fire the malware/KEV blocks. A snapshot with no
-- components has nothing to scan and is ready immediately (coverage-only or
-- SARIF-only uploads). latest_status lets the caller word "failed" apart from
-- "in progress".
SELECT
    EXISTS(SELECT 1 FROM scans sc WHERE sc.snapshot_id = $1 AND sc.status = 'complete') AS has_complete_scan,
    EXISTS(SELECT 1 FROM scans sc WHERE sc.snapshot_id = $1) AS has_any_scan,
    EXISTS(SELECT 1 FROM snapshot_components sn WHERE sn.snapshot_id = $1) AS has_components,
    -- status is an enum: cast before COALESCE or the '' fallback fails to
    -- parse as scan_status on snapshots with no scans (observed on dogfood,
    -- which silently degraded the whole guard open).
    COALESCE((SELECT sc.status::text FROM scans sc WHERE sc.snapshot_id = $1 ORDER BY sc.created_at DESC LIMIT 1), '') AS latest_status;

-- name: FindReusableScan :one
-- A complete scan of another snapshot with the same inventory set, run
-- with the same providers after the last advisory or range change and
-- not before @not_before: its matches are the matches this snapshot
-- would get (ADR-045, Database section).
SELECT sc.id AS scan_id, sc.snapshot_id
FROM snapshots s
JOIN snapshots prior ON prior.inventory_set_id = s.inventory_set_id AND prior.id <> s.id AND prior.org_id = s.org_id
JOIN scans sc ON sc.snapshot_id = prior.id AND sc.status = 'complete'
WHERE s.id = sqlc.arg(snapshot_id)
  AND s.inventory_set_id IS NOT NULL
  AND sc.providers_requested = sqlc.arg(providers)::text[]
  AND sc.completed_at > sqlc.arg(not_before)::timestamptz
  AND sc.completed_at > GREATEST(
        COALESCE((SELECT max(a.updated_at) FROM advisories a), '-infinity'::timestamptz),
        COALESCE((SELECT max(r.created_at) FROM affected_ranges r), '-infinity'::timestamptz))
ORDER BY sc.completed_at DESC
LIMIT 1;

-- name: MarkScanReused :exec
UPDATE scans SET reused_from_scan_id = sqlc.arg(from_scan_id) WHERE id = sqlc.arg(id);
