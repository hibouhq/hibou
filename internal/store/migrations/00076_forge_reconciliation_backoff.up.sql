CREATE TABLE forge_reconciliation_backoff (
    provider text PRIMARY KEY,
    retry_after timestamptz NOT NULL
);
CREATE INDEX forge_repositories_account_identity_idx
    ON forge_repositories(provider,lower(account_login),account_id)
    WHERE removed_at IS NULL AND account_id<>'';
