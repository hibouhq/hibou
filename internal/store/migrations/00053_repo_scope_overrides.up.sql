-- ADR-035 §3 / ADR-036 §2: repository owners refine detection — exclude a
-- path (generated code, fixtures) or declare a module root the recipes miss.
-- An exclusion that removes code in a language the org requires scanned only
-- applies once an exception for that path is approved.
CREATE TABLE repo_scope_overrides (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('exclude', 'module_root')),
    path text NOT NULL CHECK (length(trim(path)) > 0),
    reason text NOT NULL CHECK (length(trim(reason)) > 0),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (repo_id, kind, path)
);
