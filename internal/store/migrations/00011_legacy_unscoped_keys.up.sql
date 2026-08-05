-- Make the "legacy unscoped token" model real. The original schema declared
-- scopes NOT NULL DEFAULT '[]', so pre-ADR-020 rows hold '[]' or '["all"]' —
-- which the scope parser treats as present-but-malformed and therefore
-- DENIES EVERYTHING. Upgrading would have bricked every existing token.
--
-- Arrays were only ever those legacy sentinels (no array shape was ever a
-- valid scope), so any array collapses to the JSON null document: the explicit
-- representation of "legacy unscoped, full owner RBAC" that the application
-- already recognizes. The column stays NOT NULL — jsonb 'null' is the
-- sentinel, never SQL NULL. New tokens always carry an object scope; minting
-- without one is rejected at the API layer.

ALTER TABLE api_keys
    ALTER COLUMN scopes SET DEFAULT 'null'::jsonb;

UPDATE api_keys SET scopes = 'null'::jsonb WHERE jsonb_typeof(scopes) = 'array';
