-- Only restore if no duplicate emails exist (forward-only in practice).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT email FROM users GROUP BY email HAVING COUNT(*) > 1
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
  ELSE
    RAISE WARNING 'Cannot restore users_email_key: duplicate emails exist';
  END IF;
END $$;
