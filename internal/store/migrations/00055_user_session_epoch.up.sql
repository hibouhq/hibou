-- Session revocation: every session cookie is signed over its user's epoch.
-- Logout bumps it, so a stolen or still-open cookie stops authenticating.
ALTER TABLE users ADD COLUMN session_epoch bigint NOT NULL DEFAULT 0;
