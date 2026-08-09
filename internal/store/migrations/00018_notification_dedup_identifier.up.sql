-- Per-finding notification dedup (dogfood round 2, item 2): the same CVE was
-- re-notified on every scan because vulnerabilities are per-snapshot rows.
-- The ledger gains the human-facing identifier; existing rows (stale-scan,
-- token-expiry) keep '' and their (event_type, id) semantics.
ALTER TABLE notification_dedup
    ADD COLUMN identifier text NOT NULL DEFAULT '';

ALTER TABLE notification_dedup DROP CONSTRAINT notification_dedup_pkey;
ALTER TABLE notification_dedup ADD PRIMARY KEY (event_type, repo_id, identifier);
