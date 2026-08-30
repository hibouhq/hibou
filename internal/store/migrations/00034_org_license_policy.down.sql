DROP INDEX IF EXISTS license_policies_one_enabled_per_org;

ALTER TABLE license_policies
    DROP COLUMN IF EXISTS denied_categories,
    DROP COLUMN IF EXISTS exempt_purls,
    DROP COLUMN IF EXISTS deny_unknown,
    DROP COLUMN IF EXISTS evaluate,
    DROP COLUMN IF EXISTS updated_by;
