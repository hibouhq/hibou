-- Package policy acceptances (ADR-048 §3): the designed exit from a
-- cooldown hold. One row per (org, repo or org-wide, purl), with a reason
-- and an optional expiry, recorded by a person. An acceptance makes the
-- policy endpoint, the gate and the MCP tool answer "allow" for that exact
-- version; it never widens to a package or a range.
CREATE TABLE package_policy_acceptances (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL means the whole organization.
    repo_id uuid REFERENCES repositories(id) ON DELETE CASCADE,
    purl text NOT NULL,
    reason text NOT NULL,
    accepted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

-- One acceptance per scope: the org-wide row and a repo row may coexist.
CREATE UNIQUE INDEX package_policy_acceptances_scope_key
    ON package_policy_acceptances (org_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), purl);

CREATE INDEX package_policy_acceptances_org_purl_idx
    ON package_policy_acceptances (org_id, purl);
