UPDATE api_keys SET scopes = '[]'::jsonb WHERE scopes = 'null'::jsonb;

ALTER TABLE api_keys
    ALTER COLUMN scopes SET DEFAULT '[]'::jsonb;
