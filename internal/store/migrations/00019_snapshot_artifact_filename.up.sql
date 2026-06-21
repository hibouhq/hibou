-- Persist the original uploaded filename so downloads can round-trip the exact
-- name the client sent (instead of a name derived from kind/format/tool).
ALTER TABLE snapshot_artifacts ADD COLUMN filename TEXT NOT NULL DEFAULT '';
