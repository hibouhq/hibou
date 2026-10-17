-- Not-shipped list entries (ADR-045 §6): components that never reach
-- clients, kept listed with shipped: no. One row per (org, repo or
-- org-wide, pattern), with a reason and who recorded it. The .hibou.yaml
-- list and the built-in defaults are not stored here; the shipping policy
-- merges all of them at read time.
CREATE TABLE not_shipped_entries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL means the whole organization.
    repo_id uuid REFERENCES repositories(id) ON DELETE CASCADE,
    pattern text NOT NULL,
    reason text NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX not_shipped_entries_scope_key
    ON not_shipped_entries (org_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), pattern);

CREATE INDEX not_shipped_entries_org_repo_idx ON not_shipped_entries (org_id, repo_id);
