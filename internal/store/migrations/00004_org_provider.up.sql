ALTER TABLE organizations ADD COLUMN provider TEXT NOT NULL DEFAULT 'github';
ALTER TABLE organizations DROP CONSTRAINT organizations_slug_key;
ALTER TABLE organizations ADD CONSTRAINT organizations_provider_slug_key UNIQUE (provider, slug);
