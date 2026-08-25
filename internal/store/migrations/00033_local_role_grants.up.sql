-- Operator-granted roles, and the record of ones the forge caused us to suspend.
--
-- Casbin holds only ACTIVE grants, so enforcement never has to reason about a
-- suspended-but-present policy — a grant is either in the policy set or it is
-- not. This table is the record around that: who granted it, and if it is
-- currently suspended, why.
--
-- Suspension exists because a forge downgrade is ambiguous. Someone moved from
-- admin to viewer either because their responsibilities changed or because a
-- team was reorganised, and only one of those means they should keep authoring
-- advisory data. Revoking outright would silently break a triage queue on a
-- reorg; keeping the grant would leave a demoted admin able to create findings
-- across every repository. Suspend-and-notify is recoverable in one click and
-- safe in the meantime.
--
-- Removal from the org is NOT ambiguous and is not a suspension: the person may
-- have left the company, so the row goes with them.
CREATE TABLE local_role_grants (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL,
    -- NULL means instance-wide.
    org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    suspended_at timestamp with time zone,
    suspended_reason text DEFAULT ''::text NOT NULL,
    UNIQUE (user_id, role, org_id)
);

CREATE INDEX local_role_grants_user_idx ON local_role_grants (user_id);
CREATE INDEX local_role_grants_suspended_idx ON local_role_grants (suspended_at)
    WHERE suspended_at IS NOT NULL;
