CREATE TABLE audit_logs_plain (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    actor_type text DEFAULT 'user'::text NOT NULL,
    actor_display text DEFAULT ''::text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    org_id uuid,
    context jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_address text DEFAULT ''::text NOT NULL,
    user_agent text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO audit_logs_plain
SELECT id, actor_id, actor_type, actor_display, action, resource_type, resource_id, org_id, context, ip_address, user_agent, created_at
FROM audit_logs;

DROP TABLE audit_logs;

ALTER TABLE audit_logs_plain RENAME TO audit_logs;

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE SET NULL;

-- Restored NOT VALID: rows written under ADR-020 hold API-key ids in actor_id,
-- which the old users(id) FK would reject.
ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_actor_id_fkey
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL NOT VALID;

CREATE INDEX idx_audit_logs_action ON audit_logs USING btree (action);

CREATE INDEX idx_audit_logs_actor ON audit_logs USING btree (actor_id);

CREATE INDEX idx_audit_logs_created ON audit_logs USING btree (created_at);

CREATE INDEX idx_audit_logs_created_brin ON audit_logs USING brin (created_at);

CREATE INDEX idx_audit_logs_org ON audit_logs USING btree (org_id);

CREATE INDEX idx_audit_logs_resource ON audit_logs USING btree (resource_type, resource_id);
