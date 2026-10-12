-- ADR-034: finding presence only needs which files changed between two
-- branch snapshots, never the hunks. Those comparisons are cached as paths
-- and status only; a paths-only row never serves the annotated diff view
-- (it re-fetches and upgrades the row), and a full row is never downgraded.
ALTER TABLE compare_patch_cache ADD COLUMN paths_only boolean NOT NULL DEFAULT false;
