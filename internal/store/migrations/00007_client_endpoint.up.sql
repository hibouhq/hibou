ALTER TABLE clients ADD COLUMN endpoint TEXT;
ALTER TABLE clients ADD COLUMN client_type TEXT NOT NULL DEFAULT 'external';
