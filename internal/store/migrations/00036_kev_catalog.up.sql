-- Known-exploited-vulnerabilities catalogs (ADR-032), mirrored locally so gate
-- evaluation and finding detail never call out to a publisher on a request
-- path. CISA KEV and the ENISA EUVD exploited set sync side by side, the model
-- Dependency-Track 5.1 ships.
--
-- One row per (source, cve_id): each sync pass owns exactly its source's rows,
-- so one catalog's replace can never delete another's; membership checks stay
-- a union — being on ANY catalog is the "actively exploited" fact the gate
-- blocks on. EUVD entries are stored under their CVE alias (exploited entries
-- without one cannot match an advisory today and are skipped and counted by
-- the sync).
--
-- The sync replaces a source's rows wholesale on every pass: publishers
-- occasionally withdraw an entry, and a row that lingers after withdrawal
-- would keep failing gates on a judgement the publisher has retracted. At a
-- few thousand rows a full replace is cheaper than tracking deltas.
--
-- cve_id is stored uppercase; the sync normalizes on write so lookups can be a
-- plain equality join instead of upper() on both sides of every query.
CREATE TABLE kev_entries (
    source text NOT NULL,
    cve_id text NOT NULL,
    vendor_project text DEFAULT ''::text NOT NULL,
    product text DEFAULT ''::text NOT NULL,
    vulnerability_name text DEFAULT ''::text NOT NULL,
    -- When the publisher listed the entry as exploited — the date exploitation
    -- became a recorded fact, which is the date a reader triaging a finding
    -- wants (CISA's dateAdded; EUVD's exploitedSince).
    date_added date,
    -- CISA's remediation deadline for US federal agencies (BOD 22-01). Not
    -- binding on anyone else, but a widely used urgency signal. CISA-only.
    due_date date,
    -- True when CISA marks the entry as used in ransomware campaigns.
    known_ransomware_campaign_use boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (source, cve_id)
);

-- updated_at is "when the source's catalog last contained this row", not
-- "when its fields last changed": the EUVD sync deletes unseen rows only
-- after a grace window (its paginated walk has no stable order, so a record
-- can be skipped once), and that window is measured against updated_at.
COMMENT ON COLUMN kev_entries.updated_at IS
    'When the source''s catalog last contained this row (last seen), not when its fields last changed.';

-- Serves cve_id-only lookups (gate membership, finding detail), which probe
-- across ALL sources; the primary key leads with source, so it cannot.
CREATE INDEX kev_entries_cve_id_idx ON kev_entries (cve_id);
