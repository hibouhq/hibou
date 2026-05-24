ALTER TABLE organizations DROP CONSTRAINT organizations_provider_slug_key;
ALTER TABLE organizations ADD CONSTRAINT organizations_slug_key UNIQUE (slug);
ALTER TABLE organizations DROP COLUMN provider;
