DROP INDEX IF EXISTS organizations_forge_account_id_key;
ALTER TABLE organizations
    DROP COLUMN IF EXISTS forge_account_login,
    DROP COLUMN IF EXISTS forge_account_id;
