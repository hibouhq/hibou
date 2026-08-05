CREATE TYPE finding_origin AS ENUM (
    'scanner',
    'human',
    'agent'
);

ALTER TABLE vulnerabilities
    ADD COLUMN origin finding_origin DEFAULT 'scanner'::finding_origin NOT NULL,
    ADD COLUMN origin_api_key_id uuid,
    ADD COLUMN origin_token_name text DEFAULT ''::text NOT NULL,
    ADD COLUMN origin_owner_type text DEFAULT ''::text NOT NULL,
    ADD COLUMN origin_owner_id uuid;

-- The live link: revoking a token must be able to find every finding it filed.
-- Deleting the key nulls the link but leaves origin_token_name and the owner
-- columns, so provenance survives revocation.
ALTER TABLE vulnerabilities
    ADD CONSTRAINT vulnerabilities_origin_api_key_id_fkey
        FOREIGN KEY (origin_api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL;

-- An accountable principal is required for anything a scanner did not produce:
-- a human finding names its author, an agent finding names its token owner.
ALTER TABLE vulnerabilities
    ADD CONSTRAINT vulnerabilities_origin_human_actor
        CHECK ((origin <> 'human'::finding_origin) OR (created_by IS NOT NULL)),
    ADD CONSTRAINT vulnerabilities_origin_agent_owner
        CHECK ((origin <> 'agent'::finding_origin) OR (origin_owner_type <> ''::text AND origin_owner_id IS NOT NULL)),
    ADD CONSTRAINT vulnerabilities_origin_owner_type
        CHECK (origin_owner_type IN (''::text, 'user'::text, 'org'::text));

CREATE INDEX idx_vulnerabilities_origin_api_key ON vulnerabilities USING btree (origin_api_key_id) WHERE (origin_api_key_id IS NOT NULL);

CREATE INDEX idx_vulnerabilities_origin ON vulnerabilities USING btree (org_id, origin) WHERE (origin <> 'scanner'::finding_origin);
