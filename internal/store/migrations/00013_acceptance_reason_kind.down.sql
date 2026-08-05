DROP INDEX IF EXISTS finding_acceptances_labels_gin;

ALTER TABLE finding_acceptances
    ADD COLUMN status text;

UPDATE finding_acceptances
SET status = CASE WHEN reason_kind = 'false_positive' THEN 'false_positive' ELSE 'accepted' END;

ALTER TABLE finding_acceptances
    ALTER COLUMN status SET NOT NULL;

ALTER TABLE finding_acceptances
    ADD CONSTRAINT finding_acceptances_status_check CHECK (status IN ('accepted', 'false_positive'));

ALTER TABLE finding_acceptances
    DROP COLUMN vex_justification,
    DROP COLUMN labels,
    DROP COLUMN reason_kind;

DROP TYPE acceptance_reason_kind;
