-- Allow same email across different forge providers.
-- The real identity key is (provider, provider_id).
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
