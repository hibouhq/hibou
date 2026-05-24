ALTER TABLE clients ADD COLUMN endpoint TEXT;
UPDATE clients SET endpoint = labels->>'endpoint' WHERE labels->>'endpoint' IS NOT NULL;
ALTER TABLE clients DROP COLUMN IF EXISTS labels;