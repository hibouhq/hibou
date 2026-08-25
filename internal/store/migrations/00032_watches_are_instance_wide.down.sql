ALTER TABLE cve_subscriptions ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS cve_subscriptions_org_idx ON cve_subscriptions (org_id);

ALTER TABLE advisory_events ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS advisory_events_org_idx ON advisory_events (org_id, occurred_at DESC);
DROP INDEX IF EXISTS advisory_events_kind_idx;
