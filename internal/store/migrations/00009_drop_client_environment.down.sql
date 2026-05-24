ALTER TABLE clients ADD COLUMN environment TEXT NOT NULL DEFAULT 'production';
UPDATE clients SET environment = COALESCE(labels->>'environment', 'production');
UPDATE clients SET labels = labels - 'environment';
ALTER TABLE clients ALTER COLUMN environment DROP DEFAULT;
