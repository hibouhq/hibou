-- Security audit §3.1/§3.3: an organization is bound to exactly one forge
-- account. The login is what installation tokens are minted by, so every
-- repo-scoped forge call checks the repository owner against it; the numeric
-- account id is what provisioning matches on, because a login can be renamed
-- and re-registered by someone else, and distinct logins can slugify alike.
ALTER TABLE organizations
    ADD COLUMN forge_account_id text,
    ADD COLUMN forge_account_login text;

-- One Hibou org per forge account. NULL ids (legacy rows, manual orgs) are
-- backfilled on the next verified installation event.
CREATE UNIQUE INDEX organizations_forge_account_id_key
    ON organizations (provider, forge_account_id)
    WHERE forge_account_id IS NOT NULL;

-- Backfill the login from the provisioning binding, only where it is
-- unambiguous (a single account was ever bound to the org).
UPDATE organizations o
SET forge_account_login = b.account
FROM (
    SELECT org_id, provider, min(account) AS account
    FROM forge_org_admins
    WHERE org_id IS NOT NULL
    GROUP BY org_id, provider
    HAVING count(DISTINCT lower(account)) = 1
) b
WHERE b.org_id = o.id AND b.provider = o.provider;
