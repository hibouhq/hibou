-- The repo_scoped data fix is not reverted: un-scoping would widen access.
ALTER TABLE org_members DROP COLUMN repo_scope_at;
ALTER TABLE org_members DROP COLUMN revalidation_attempted_at;
