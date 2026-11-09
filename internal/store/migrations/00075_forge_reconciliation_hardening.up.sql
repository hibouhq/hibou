ALTER TABLE forge_repositories ADD COLUMN account_id text NOT NULL DEFAULT '';

CREATE TABLE forge_repository_bindings (
    repo_id uuid PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    provider text NOT NULL,
    account_id text NOT NULL CHECK (account_id <> ''),
    repository_id text NOT NULL CHECK (repository_id <> '')
);

-- Anchor existing enrollments before a later inventory observation can reuse
-- their mutable owner/name. Live reads additionally require the account ID
-- supplied by the current App installation, never just its login.
INSERT INTO forge_repository_bindings(repo_id,provider,account_id,repository_id)
SELECT DISTINCT ON (r.id) r.id,r.provider,o.forge_account_id,f.provider_repo_id
FROM repositories r
JOIN organizations o ON o.id=r.org_id
JOIN forge_repositories f ON f.provider=r.provider AND lower(f.provider_key)=lower(r.provider_id)
WHERE o.forge_account_id<>'' AND COALESCE(f.provider_repo_id,'')<>''
AND lower(f.account_login)=lower(o.forge_account_login)
ORDER BY r.id,f.updated_at DESC;

CREATE INDEX forge_reconciliation_runs_job_time_idx
    ON forge_reconciliation_runs(job_id,started_at DESC);
