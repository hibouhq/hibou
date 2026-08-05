DELETE FROM api_keys WHERE user_id IS NULL;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_user_id_fkey;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE api_keys
    ALTER COLUMN user_id SET NOT NULL;
