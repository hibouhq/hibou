-- ADR-028: triage is instance-wide, so a watch has no organization.
--
-- Scope was briefly a per-row choice, and neither deployment wanted it: on a
-- single-company instance every org is the same company, so org scope only
-- meant watching the same product repeatedly; on a multi-tenant one a customer
-- authoring for the others is a cross-tenant escalation, which is served by
-- centrally curated advisories shipped as data instead. Removing the column
-- makes that escalation unrepresentable rather than guarded against.
--
-- IF EXISTS because 00031 shipped both shapes: an instance that applied the
-- earlier version has these columns, a fresh one never created them.
DROP INDEX IF EXISTS cve_subscriptions_org_idx;
ALTER TABLE cve_subscriptions DROP COLUMN IF EXISTS org_id;

DROP INDEX IF EXISTS advisory_events_org_idx;
ALTER TABLE advisory_events DROP COLUMN IF EXISTS org_id;
CREATE INDEX IF NOT EXISTS advisory_events_kind_idx ON advisory_events (kind, occurred_at DESC);
