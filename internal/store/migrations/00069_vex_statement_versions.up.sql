-- +goose Up
-- VEX statements as the only source of truth (ADR-053 §4a, amending ADR-009
-- and ADR-023). A statement gains a product axis — one release, or a vers
-- range over the repository's releases, or neither for the whole repository —
-- and becomes insert-only: a change inserts a row that supersedes the previous
-- one, a withdrawal inserts a withdrawn row. The current statement is the one
-- nothing supersedes and that is not withdrawn.

ALTER TABLE vex_statements
    ADD COLUMN release_id    uuid REFERENCES releases(id) ON DELETE CASCADE,
    ADD COLUMN version_range text,
    ADD COLUMN evidence      jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN supersedes    uuid REFERENCES vex_statements(id) ON DELETE CASCADE,
    ADD COLUMN withdrawn     boolean NOT NULL DEFAULT false,
    ADD COLUMN approved_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN approved_at   timestamptz,
    ADD CONSTRAINT vex_product_axis_single CHECK (release_id IS NULL OR version_range IS NULL),
    ADD CONSTRAINT vex_product_axis_needs_repo CHECK ((release_id IS NULL AND version_range IS NULL) OR repo_id IS NOT NULL);

-- A statement's content is never edited. Superseding stamps the old row's
-- `superseded_at` and nothing else, so the database can keep guaranteeing one
-- current statement per scope (the partial unique index below replaces the
-- old full one, which allowed no history at all).
ALTER TABLE vex_statements ADD COLUMN superseded_at timestamptz;
DROP INDEX idx_vex_statements_scope;
CREATE UNIQUE INDEX idx_vex_statements_current_scope ON vex_statements (
    org_id,
    advisory_id,
    COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid),
    COALESCE(component_purl, ''),
    COALESCE(release_id, '00000000-0000-0000-0000-000000000000'::uuid),
    COALESCE(version_range, '')
) WHERE superseded_at IS NULL;

-- A statement is superseded at most once: the chain never forks.
CREATE UNIQUE INDEX vex_statements_supersedes_once ON vex_statements (supersedes) WHERE supersedes IS NOT NULL;
CREATE INDEX vex_statements_release_idx ON vex_statements (release_id) WHERE release_id IS NOT NULL;

-- The triage decision writes the statement; the acceptance points at it.
ALTER TABLE finding_acceptances
    ADD COLUMN vex_statement_id uuid REFERENCES vex_statements(id) ON DELETE SET NULL;

-- A vulnerability in the product's own code (ADR-053 §4a). The canonical
-- advisory row carries the identifier (a CVE, or a vendor identifier until one
-- exists); this row says whose product it is and which versions it affects.
CREATE TABLE first_party_advisories (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id        uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    advisory_id    uuid NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    product_purl   text NOT NULL,
    product_cpe    text,
    affected_range text NOT NULL,
    promoted_from  text,
    created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repo_id, advisory_id)
);
CREATE INDEX first_party_advisories_org_idx ON first_party_advisories (org_id);
