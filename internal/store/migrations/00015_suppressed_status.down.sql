-- Postgres cannot drop an enum value; rebuild the type. Suppressed rows fold
-- into 'dismissed' (the closest pre-existing "not open risk" state).
UPDATE vulnerabilities
SET status = 'dismissed',
    dismissal_reason = COALESCE(dismissal_reason, 'not_applicable'),
    state_comment = COALESCE(NULLIF(state_comment, ''), 'suppressed in scanner source')
WHERE status = 'suppressed';

UPDATE vulnerability_state_transitions SET state = 'dismissed' WHERE state = 'suppressed';

ALTER TYPE vulnerability_status RENAME TO vulnerability_status_old;
CREATE TYPE vulnerability_status AS ENUM ('detected', 'confirmed', 'dismissed', 'resolved');
ALTER TABLE vulnerabilities ALTER COLUMN status DROP DEFAULT;
ALTER TABLE vulnerabilities
    ALTER COLUMN status TYPE vulnerability_status USING status::text::vulnerability_status;
ALTER TABLE vulnerabilities ALTER COLUMN status SET DEFAULT 'detected';
ALTER TABLE vulnerability_state_transitions
    ALTER COLUMN state TYPE vulnerability_status USING state::text::vulnerability_status;
DROP TYPE vulnerability_status_old;
