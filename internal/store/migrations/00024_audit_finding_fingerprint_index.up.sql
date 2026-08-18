-- The finding-history endpoint reads the audit log keyed by fingerprint (one
-- lookup per detail-drawer open), a shape none of the existing audit indexes
-- serve: without this it degrades to a partition-wide scan on a table built to
-- grow forever. Partial, because only triage-flavoured entries carry a
-- fingerprint at all.
CREATE INDEX IF NOT EXISTS idx_audit_logs_finding
    ON audit_logs USING btree (org_id, (context->>'fingerprint'), created_at DESC)
    WHERE context ? 'fingerprint';
