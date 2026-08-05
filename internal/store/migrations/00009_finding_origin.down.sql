DROP INDEX IF EXISTS idx_vulnerabilities_origin;

DROP INDEX IF EXISTS idx_vulnerabilities_origin_api_key;

ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS vulnerabilities_origin_owner_type,
    DROP CONSTRAINT IF EXISTS vulnerabilities_origin_agent_owner,
    DROP CONSTRAINT IF EXISTS vulnerabilities_origin_human_actor,
    DROP CONSTRAINT IF EXISTS vulnerabilities_origin_api_key_id_fkey;

ALTER TABLE vulnerabilities
    DROP COLUMN origin_owner_id,
    DROP COLUMN origin_owner_type,
    DROP COLUMN origin_token_name,
    DROP COLUMN origin_api_key_id,
    DROP COLUMN origin;

DROP TYPE finding_origin;
