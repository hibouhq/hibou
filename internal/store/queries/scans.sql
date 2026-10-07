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
    COALESCE((SELECT sc.status FROM scans sc WHERE sc.snapshot_id = $1 ORDER BY sc.created_at DESC LIMIT 1), '') AS latest_status;
