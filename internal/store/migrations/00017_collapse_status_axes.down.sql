-- Restores the old vocabulary and columns. The folded data is not
-- reconstructed: dismissals live on as acceptance rows (which the old code
-- also understood), confirmed rows stay detected.
CREATE TYPE dismissal_reason AS ENUM (
    'acceptable_risk',
    'false_positive',
    'mitigating_control',
    'not_applicable',
    'used_in_tests'
);

ALTER TABLE vulnerabilities
    ADD COLUMN confirmed_at timestamp with time zone,
    ADD COLUMN confirmed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN dismissed_at timestamp with time zone,
    ADD COLUMN dismissed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN dismissal_reason dismissal_reason;

ALTER TYPE vulnerability_status RENAME TO vulnerability_status_new;
CREATE TYPE vulnerability_status AS ENUM ('detected', 'confirmed', 'dismissed', 'resolved', 'suppressed');
ALTER TABLE vulnerabilities ALTER COLUMN status DROP DEFAULT;
ALTER TABLE vulnerabilities
    ALTER COLUMN status TYPE vulnerability_status USING status::text::vulnerability_status;
ALTER TABLE vulnerabilities ALTER COLUMN status SET DEFAULT 'detected';
ALTER TABLE vulnerability_state_transitions
    ALTER COLUMN state TYPE vulnerability_status USING state::text::vulnerability_status;
DROP TYPE vulnerability_status_new;
