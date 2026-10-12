-- ADR-034 §3 (D1): a produced finding missing from a new snapshot is copied
-- into it ("carried forward") unless its producer re-checked it. Carried rows
-- keep counting as open everywhere that reads a snapshot's rows; presence
-- says why they are there.
CREATE TYPE finding_presence AS ENUM ('reported', 'not_rechecked', 'unconfirmed');

ALTER TABLE vulnerabilities
    ADD COLUMN presence finding_presence NOT NULL DEFAULT 'reported',
    -- Why a carried row was not re-checked: producer_missing,
    -- producer_failed, producer_pending, outside_scope, partial_scope,
    -- partial_run, file_skipped:<reason>.
    ADD COLUMN presence_reason text,
    -- Where the producer last actually reported the finding.
    ADD COLUMN last_seen_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    ADD COLUMN last_seen_commit text,
    -- Covered scans in a row without the finding (ADR-034 §5,
    -- consecutive-absence:N).
    ADD COLUMN consecutive_absences integer NOT NULL DEFAULT 0;

-- Carried rows are the minority; the reconcile step reads only them.
CREATE INDEX vulnerabilities_carried_idx
    ON vulnerabilities (snapshot_id) WHERE presence <> 'reported';
