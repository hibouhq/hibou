ALTER TABLE clients ADD COLUMN labels JSONB NOT NULL DEFAULT '{}';
UPDATE clients SET labels = jsonb_build_object('endpoint', endpoint) WHERE endpoint IS NOT NULL;
ALTER TABLE clients DROP COLUMN endpoint;