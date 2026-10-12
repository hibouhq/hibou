-- ADR-035 §5: which scanners run on a repository. Repo owners choose per
-- scanner (inherit / enabled / disabled); org admins may require a
-- capability for a language, which a repo cannot loosen without an approved,
-- reasoned, expiring exception. All of it is org state edited through the
-- API and UI (D11), so no pull request can change it.
CREATE TABLE repo_scanner_settings (
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scanner_id text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('inherit', 'enabled', 'disabled')),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (repo_id, scanner_id)
);

CREATE TABLE scanner_requirements (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- e.g. java + cross-file-taint, java + bytecode-security.
    language text NOT NULL,
    capability text NOT NULL,
    -- Approved scanners; empty = any catalog scanner with the capability.
    scanner_ids text[] NOT NULL DEFAULT '{}',
    -- A run older than this does not satisfy the requirement (0 = no limit).
    freshness_days integer NOT NULL DEFAULT 0 CHECK (freshness_days >= 0),
    -- advisory warns; blocking fails the coverage check.
    enforcement text NOT NULL DEFAULT 'advisory' CHECK (enforcement IN ('advisory', 'blocking')),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (org_id, language, capability)
);

CREATE TABLE coverage_exceptions (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    requirement_id uuid NOT NULL REFERENCES scanner_requirements(id) ON DELETE CASCADE,
    -- A module root, or "." for the whole repository.
    scope text NOT NULL DEFAULT '.',
    reason text NOT NULL CHECK (length(trim(reason)) > 0),
    status text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'approved', 'rejected')),
    requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX coverage_exceptions_repo_idx ON coverage_exceptions (repo_id, status);
