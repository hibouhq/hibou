DROP INDEX IF EXISTS snapshot_artifacts_sha256_idx;
ALTER TABLE snapshot_artifacts
    DROP COLUMN IF EXISTS origin,
    DROP COLUMN IF EXISTS metadata,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS revoked_by,
    DROP COLUMN IF EXISTS revoke_reason,
    DROP COLUMN IF EXISTS created_by;
