-- Retain incident provenance after hard repository removal.
ALTER TABLE incidents ADD COLUMN removed_repo_name text;
