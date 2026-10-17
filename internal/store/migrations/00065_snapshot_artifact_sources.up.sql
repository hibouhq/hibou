-- Inventory sources on releases (ADR-046 §4, ADR-045 §5.3): an artifact
-- records where it came from (ci upload, server extraction, manual
-- deliverable scan), what the CLI checked about the deliverable, and
-- whether an admin revoked it. Revocation removes the artifact's
-- components from the snapshot's effective inventory; the artifact itself
-- stays, immutable, and can be restored.
ALTER TABLE snapshot_artifacts
    ADD COLUMN origin text NOT NULL DEFAULT 'ci',
    ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN revoked_at timestamp with time zone,
    ADD COLUMN revoked_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN revoke_reason text,
    ADD COLUMN created_by uuid REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX snapshot_artifacts_sha256_idx ON snapshot_artifacts (snapshot_id, sha256);
