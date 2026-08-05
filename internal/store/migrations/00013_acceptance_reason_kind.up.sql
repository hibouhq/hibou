-- ADR-023: one decision (accepted), one dimension of justification.
-- "false positive" stops being a status and becomes a reason_kind; labels are
-- the open, semantics-free tracking layer; vex_justification carries the
-- standard vocabulary for dependency false-positives.

CREATE TYPE acceptance_reason_kind AS ENUM (
    'risk_accepted',
    'false_positive'
);

ALTER TABLE finding_acceptances
    ADD COLUMN reason_kind acceptance_reason_kind,
    ADD COLUMN labels text[] NOT NULL DEFAULT '{}',
    ADD COLUMN vex_justification vex_justification;

UPDATE finding_acceptances
SET reason_kind = CASE WHEN status = 'false_positive'
    THEN 'false_positive'::acceptance_reason_kind
    ELSE 'risk_accepted'::acceptance_reason_kind END;

ALTER TABLE finding_acceptances
    ALTER COLUMN reason_kind SET NOT NULL;

-- Row existence IS the accepted decision; the status column carried nothing
-- else once false_positive collapsed into reason_kind.
ALTER TABLE finding_acceptances
    DROP COLUMN status;

CREATE INDEX finding_acceptances_labels_gin ON finding_acceptances USING gin (labels);
