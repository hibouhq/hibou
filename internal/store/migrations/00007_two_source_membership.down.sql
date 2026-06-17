DROP TABLE IF EXISTS user_repo_access;

DROP INDEX IF EXISTS org_members_org_id_source_idx;

ALTER TABLE org_members
    DROP CONSTRAINT IF EXISTS org_members_source_check,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS synced_at,
    DROP COLUMN IF EXISTS source;