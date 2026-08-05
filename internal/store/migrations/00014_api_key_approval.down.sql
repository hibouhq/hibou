-- Pending/rejected tokens never authenticated, so dropping the columns simply
-- activates them; delete them instead so a rollback cannot grant access.
DELETE FROM api_keys WHERE approval_status <> 'approved';

ALTER TABLE api_keys
    DROP COLUMN approval_status,
    DROP COLUMN approved_by,
    DROP COLUMN approved_at;

DROP TYPE api_key_approval_status;
