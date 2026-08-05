-- ADR-022 amendment: member-requested org tokens with admin approval.
-- Like GitHub fine-grained PATs targeting an org: any member can mint an
-- org-owned token, but it stays pending — and fails authentication — until an
-- org admin approves it. Existing rows (and all user-owned keys) are approved.
CREATE TYPE api_key_approval_status AS ENUM ('pending', 'approved', 'rejected');

ALTER TABLE api_keys
    ADD COLUMN approval_status api_key_approval_status NOT NULL DEFAULT 'approved',
    ADD COLUMN approved_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN approved_at timestamptz;
