-- Close abandoned scans before enforcing per-snapshot exclusion. Recent
-- duplicates deliberately fail index creation: stop the old workers and
-- resolve those scans before retrying, rather than cancelling live writers.
UPDATE scans
SET status = 'cancelled',
    error_message = 'cancelled by migration 00083: abandoned scan',
    completed_at = now()
WHERE status IN ('pending', 'running')
  AND coalesce(started_at, created_at) < now() - interval '1 hour';

UPDATE scan_providers
SET status = 'cancelled',
    error_message = 'cancelled by migration 00083: parent scan abandoned',
    completed_at = now()
WHERE status IN ('pending', 'running')
  AND scan_id IN (SELECT id FROM scans WHERE status = 'cancelled');

CREATE UNIQUE INDEX scans_one_active_per_snapshot
    ON scans (snapshot_id)
    WHERE status IN ('pending', 'running');
