-- Range-partition audit_logs by month (ADR-020 "Audit storage & sustainability"):
-- expiring an old window becomes a DROP PARTITION instead of a large DELETE.
--
-- This rebuild also FIXES A BUG: the old table had
-- `actor_id REFERENCES users(id)`, but ADR-020 attributes token-authenticated
-- actions to the API key (`actor_type = 'api_key'`, `actor_id = <key id>`), so
-- every such insert violated the FK and the write was silently dropped. The
-- new table has no actor FK — `actor_type` says which table the id points at,
-- and an append-only log must outlive its principals anyway.

CREATE TABLE audit_logs_partitioned (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    actor_type text DEFAULT 'user'::text NOT NULL,
    actor_display text DEFAULT ''::text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    org_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
    context jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_address text DEFAULT ''::text NOT NULL,
    user_agent text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Safety net so a write can never fail for lack of a partition: rows land here
-- whenever the maintenance pass has not created their month yet.
CREATE TABLE audit_logs_default PARTITION OF audit_logs_partitioned DEFAULT;

-- Create the current and next month up front, BEFORE copying, so new writes
-- route into real partitions and only pre-migration history sits in default.
DO $$
DECLARE
    month_start date := date_trunc('month', now())::date;
    part_start date;
BEGIN
    FOR offset_months IN 0..1 LOOP
        part_start := (month_start + make_interval(months => offset_months))::date;
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF audit_logs_partitioned FOR VALUES FROM (%L) TO (%L)',
            'audit_logs_p' || to_char(part_start, 'YYYYMM'),
            part_start,
            (part_start + interval '1 month')::date
        );
    END LOOP;
END $$;

INSERT INTO audit_logs_partitioned
SELECT id, actor_id, actor_type, actor_display, action, resource_type, resource_id, org_id, context, ip_address, user_agent, created_at
FROM audit_logs;

DROP TABLE audit_logs;

ALTER TABLE audit_logs_partitioned RENAME TO audit_logs;

CREATE INDEX idx_audit_logs_action ON audit_logs USING btree (action);

CREATE INDEX idx_audit_logs_actor ON audit_logs USING btree (actor_id);

CREATE INDEX idx_audit_logs_created ON audit_logs USING btree (created_at);

CREATE INDEX idx_audit_logs_created_brin ON audit_logs USING brin (created_at);

CREATE INDEX idx_audit_logs_org ON audit_logs USING btree (org_id);

CREATE INDEX idx_audit_logs_resource ON audit_logs USING btree (resource_type, resource_id);
