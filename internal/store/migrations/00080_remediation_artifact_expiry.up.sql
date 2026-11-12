-- Register keys before object writes so crashes and failed finalization cannot
-- leave untracked private artifacts. Do not cascade: repository deletion must
-- not erase the pending object-store cleanup obligation.
CREATE TABLE remediation_artifact_expiry (
    artifact_key text PRIMARY KEY,
    job_id uuid NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX remediation_artifact_expiry_due ON remediation_artifact_expiry(expires_at);
