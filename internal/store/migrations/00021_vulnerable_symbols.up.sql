-- OSV Go advisories carry the vulnerable symbols
-- (affected[].ecosystem_specific.imports[].symbols). Stored per range so a
-- NEWLY PUBLISHED CVE can be checked against a snapshot's stored reachable-
-- symbol inventory — releases and main branches get symbol-level verdicts
-- without a rebuild.
ALTER TABLE affected_ranges
    ADD COLUMN vulnerable_symbols text[] NOT NULL DEFAULT '{}';
