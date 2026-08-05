-- ADR-022: org-owned tokens become service principals — they authorize as the
-- org itself, so the creating user is provenance, not identity.
--
-- user_id becomes nullable and its FK switches from CASCADE to SET NULL:
-- deleting a user must not delete the org's tokens (that was the exact
-- failure org ownership exists to prevent). A user-owned key whose owner is
-- gone is dead — the auth layer rejects owner_type='user' rows with a NULL
-- user_id, and they can be purged at leisure.

ALTER TABLE api_keys
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_user_id_fkey;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
