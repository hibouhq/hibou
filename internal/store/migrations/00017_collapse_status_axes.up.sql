-- ADR-023, final step: the status column is the machine-owned observation
-- axis only — detected | resolved | suppressed. The old human-decision
-- statuses move to where decisions live:
--   dismissed  → an acceptance row (the decision) + status back to detected
--   confirmed  → detected (a "yes it's real" note was never a distinct state)
-- Nothing has been able to write either value since the triage rework; this
-- migrates the stragglers and deletes the vocabulary.

-- 1. Preserve old dismissals as acceptances. dismissal_reason
--    'false_positive' keeps its meaning; every other reason was a flavor of
--    accepting the risk.
INSERT INTO finding_acceptances (repo_id, fingerprint, reason_kind, reason, accepted_by, created_at)
SELECT DISTINCT ON (v.repo_id, v.fingerprint)
    v.repo_id,
    v.fingerprint,
    CASE WHEN v.dismissal_reason = 'false_positive'
         THEN 'false_positive'::acceptance_reason_kind
         ELSE 'risk_accepted'::acceptance_reason_kind END,
    COALESCE(NULLIF(v.state_comment, ''),
             'migrated from dismissed status (' || COALESCE(v.dismissal_reason::text, 'unspecified') || ')'),
    v.dismissed_by,
    COALESCE(v.dismissed_at, now())
FROM vulnerabilities v
WHERE v.status = 'dismissed' AND v.repo_id IS NOT NULL AND v.fingerprint <> ''
ORDER BY v.repo_id, v.fingerprint, v.dismissed_at DESC NULLS LAST
ON CONFLICT (repo_id, fingerprint) DO NOTHING;

-- 2. Fold the statuses.
UPDATE vulnerabilities SET status = 'detected' WHERE status IN ('confirmed', 'dismissed');
UPDATE vulnerability_state_transitions SET state = 'detected' WHERE state IN ('confirmed', 'dismissed');

-- 3. Rebuild the enum without the decision values.
ALTER TYPE vulnerability_status RENAME TO vulnerability_status_old;
CREATE TYPE vulnerability_status AS ENUM ('detected', 'resolved', 'suppressed');
ALTER TABLE vulnerabilities ALTER COLUMN status DROP DEFAULT;
ALTER TABLE vulnerabilities
    ALTER COLUMN status TYPE vulnerability_status USING status::text::vulnerability_status;
ALTER TABLE vulnerabilities ALTER COLUMN status SET DEFAULT 'detected';
ALTER TABLE vulnerability_state_transitions
    ALTER COLUMN state TYPE vulnerability_status USING state::text::vulnerability_status;
DROP TYPE vulnerability_status_old;

-- 4. Drop the decision bookkeeping columns and their orphaned type.
ALTER TABLE vulnerabilities
    DROP COLUMN confirmed_at,
    DROP COLUMN confirmed_by,
    DROP COLUMN dismissed_at,
    DROP COLUMN dismissed_by,
    DROP COLUMN dismissal_reason;
DROP TYPE dismissal_reason;
