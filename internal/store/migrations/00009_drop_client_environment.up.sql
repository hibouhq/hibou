UPDATE clients
SET labels = labels || jsonb_build_object('environment', environment)
WHERE environment IS NOT NULL AND environment != '';

ALTER TABLE clients DROP COLUMN environment;
