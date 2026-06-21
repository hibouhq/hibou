-- Irreversible data collapse; restore the column only (head/merge split is lost).
ALTER TABLE refs ADD COLUMN pr_ref_kind TEXT NOT NULL DEFAULT '';
