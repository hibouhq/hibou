-- Saved filter-bar queries. A preset is the bar text a user sees, nothing
-- more: ref, snapshot, sort and page are navigation context, not part of it.
--
-- Only personal presets exist today. scope_type/scope_id are reserved so that
-- org- or repo-shared presets can be added later by widening the CHECK, with
-- no data migration; a personal preset has no scope_id.
CREATE TABLE search_presets (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type text DEFAULT 'user'::text NOT NULL,
    scope_id uuid,
    -- Which filter bar the query is written for: grammars differ per list.
    surface text NOT NULL,
    name text NOT NULL,
    query text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT search_presets_scope_check CHECK (scope_type = 'user' AND scope_id IS NULL),
    CONSTRAINT search_presets_surface_check CHECK (surface IN ('findings')),
    CONSTRAINT search_presets_name_check CHECK (char_length(btrim(name)) BETWEEN 1 AND 80),
    CONSTRAINT search_presets_query_check CHECK (char_length(btrim(query)) BETWEEN 1 AND 2000)
);

-- Names are what users pick from, so two presets differing only by case
-- would be indistinguishable in the menu.
CREATE UNIQUE INDEX search_presets_user_name_idx
    ON search_presets (owner_user_id, surface, lower(name))
    WHERE scope_type = 'user';
