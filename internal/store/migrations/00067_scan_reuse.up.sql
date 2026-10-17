-- +goose Up
-- Advisory matching runs once per distinct inventory (ADR-045, Database
-- section): a snapshot whose inventory set another snapshot already
-- scanned, after the last advisory change, copies that scan's matches.
ALTER TABLE scans ADD COLUMN reused_from_scan_id uuid REFERENCES scans(id) ON DELETE SET NULL;
CREATE INDEX scans_complete_by_snapshot_idx ON scans (snapshot_id, completed_at DESC) WHERE status = 'complete';
-- The freshness checks read the latest advisory and range change.
CREATE INDEX advisories_updated_at_idx ON advisories (updated_at);
CREATE INDEX affected_ranges_created_at_idx ON affected_ranges (created_at);
