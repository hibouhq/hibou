-- ADR-023: the manual gate override is deleted. Making a PR green means
-- triaging its findings — auditable, finding-scoped, gate-recomputing.
-- gate.override audit rows remain as history.
ALTER TABLE pr_checks
    DROP COLUMN IF EXISTS override_state,
    DROP COLUMN IF EXISTS override_reason,
    DROP COLUMN IF EXISTS override_by,
    DROP COLUMN IF EXISTS override_at;
