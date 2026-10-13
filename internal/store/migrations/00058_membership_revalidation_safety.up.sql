-- Membership re-validation must not starve: rows it could not decide on
-- (unverifiable, forge errors) are stamped here and leave the batch until
-- the next re-validation window, instead of filling every batch ahead of
-- checkable rows.
ALTER TABLE org_members ADD COLUMN revalidation_attempted_at timestamp with time zone;

-- repo_scoped is decided against the repositories enrolled when the sync
-- ran. repo_scope_at records when that was: a repository enrolled later that
-- the member holds no grant on makes the membership repository-scoped at
-- read time, until a sign-in recomputes the verdict. Without it a member
-- recorded as org-wide saw every repository enrolled after their last sync.
ALTER TABLE org_members ADD COLUMN repo_scope_at timestamp with time zone;

-- Earliest plausible sync time for existing forge rows: the oldest of their
-- grants in the org (written by the same sync), else the membership itself.
-- Earlier is safer: it can only add repositories to the "enrolled later"
-- set, and those count only when the member holds no grant on them.
UPDATE org_members om
SET repo_scope_at = COALESCE((
        SELECT MIN(COALESCE(ura.synced_at, ura.updated_at))
        FROM user_repo_access ura
        JOIN repositories r ON r.id = ura.repo_id
        WHERE ura.user_id = om.user_id AND r.org_id = om.org_id
    ), om.created_at)
WHERE om.source = 'forge';

-- 00056 only scoped members holding at least one grant in the org, so a
-- repository collaborator whose granted repositories were all removed was
-- carried over as org-wide. A forge viewer/developer with no grant in the
-- org has nothing the forge confirmed: scope them (fail closed). The next
-- sign-in recomputes the verdict from the forge.
UPDATE org_members om
SET repo_scoped = true
WHERE om.source = 'forge'
  AND om.role IN ('viewer', 'developer')
  AND NOT om.repo_scoped
  AND NOT EXISTS (
      SELECT 1
      FROM user_repo_access ura
      JOIN repositories r ON r.id = ura.repo_id
      WHERE ura.user_id = om.user_id AND r.org_id = om.org_id
  );
