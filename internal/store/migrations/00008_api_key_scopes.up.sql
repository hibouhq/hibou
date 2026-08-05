ALTER TABLE api_keys
    ADD COLUMN owner_type text NOT NULL DEFAULT 'user',
    ADD COLUMN owner_id uuid,
    ADD COLUMN description text NOT NULL DEFAULT '';