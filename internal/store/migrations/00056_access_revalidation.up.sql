-- Repository-scoped membership is an explicit fact recorded by the permission
-- sync, not inferred at read time: the old inference failed open for
-- repositories enrolled after the last sync and when a collaborator's only
-- granted repository was deleted.
ALTER TABLE org_members ADD COLUMN repo_scoped boolean NOT NULL DEFAULT false;

-- Carry the old inference over once, so nobody's visibility changes on deploy.
UPDATE org_members om
SET repo_scoped = true
WHERE om.source = 'forge'
  AND om.role IN ('viewer', 'developer')
  AND EXISTS (
      SELECT 1
      FROM user_repo_access ura
      JOIN repositories r ON r.id = ura.repo_id
      WHERE ura.user_id = om.user_id AND r.org_id = om.org_id
  )
  AND EXISTS (
      SELECT 1
      FROM repositories r
      WHERE r.org_id = om.org_id
        AND r.created_at <= (
            SELECT MAX(COALESCE(ura.synced_at, ura.updated_at))
            FROM user_repo_access ura
            JOIN repositories r2 ON r2.id = ura.repo_id
            WHERE ura.user_id = om.user_id AND r2.org_id = om.org_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM user_repo_access ura
            WHERE ura.user_id = om.user_id AND ura.repo_id = r.id
        )
  );

-- The forge login seen at the last sign-in (logins are renamable: identity
-- stays provider + provider_id), and when the sign-in allowlist last let the
-- user in through org membership. Both let token and session requests be
-- re-checked without the user's OAuth token.
ALTER TABLE users ADD COLUMN forge_login text;
ALTER TABLE users ADD COLUMN signin_allowed_at timestamp with time zone;
