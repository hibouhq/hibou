-- +goose Down
DROP INDEX affected_ranges_created_at_idx;
DROP INDEX advisories_updated_at_idx;
DROP INDEX scans_complete_by_snapshot_idx;
ALTER TABLE scans DROP COLUMN reused_from_scan_id;
