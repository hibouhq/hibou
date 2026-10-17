-- Package signals from deps.dev (ADR-048): release cooldown, registry
-- deprecation, low usage, unpublished versions and a recommended version,
-- per package version. These are attributes of a component, never
-- vulnerabilities: they live in their own table and join on purl, so one row
-- serves every repository on the instance that depends on that version.
--
-- deps.dev is a live API with no bulk export, so there is nothing to mirror
-- wholesale: the sync writes what it looked up, with fetched_at, and a
-- component without a row is "not evaluated", not "clean" (ADR-034).
-- cooldown_end is a timestamp, so "in cooldown" is computed at read time and
-- the row needs no refresh for the state to change.
--
-- malicious and vulnerable_critical record what deps.dev said so a
-- disagreement with the advisory providers can be measured; they create no
-- finding (ADR-048 §1).
CREATE TABLE package_signals (
    purl text PRIMARY KEY,
    -- deps.dev identity: system is one of NPM, PYPI, MAVEN, GO, CARGO, NUGET,
    -- RUBYGEMS; name in deps.dev's convention (Maven "group:artifact").
    system text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    published_at timestamp with time zone,
    cooldown_end timestamp with time zone,
    deprecated boolean NOT NULL DEFAULT false,
    deprecated_reason text NOT NULL DEFAULT '',
    low_usage boolean NOT NULL DEFAULT false,
    -- Package names deps.dev suggests instead of a low-usage look-alike.
    alternatives jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- The version is not on the public registry: unpublished or private.
    not_found boolean NOT NULL DEFAULT false,
    malicious boolean NOT NULL DEFAULT false,
    vulnerable_critical boolean NOT NULL DEFAULT false,
    recommended_version text NOT NULL DEFAULT '',
    -- The findings as returned, kept for forward compatibility with the
    -- v3alpha API: unknown finding types are stored here and ignored.
    raw jsonb NOT NULL DEFAULT '{}'::jsonb,
    source text NOT NULL DEFAULT 'depsdev',
    fetched_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX package_signals_fetched_at_idx ON package_signals (fetched_at);
