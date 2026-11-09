-- +goose Down
DROP TABLE first_party_advisories;
ALTER TABLE finding_acceptances DROP COLUMN vex_statement_id;
DROP INDEX vex_statements_release_idx;
DROP INDEX vex_statements_supersedes_once;
DROP INDEX idx_vex_statements_current_scope;
DELETE FROM vex_statements WHERE superseded_at IS NOT NULL OR release_id IS NOT NULL OR version_range IS NOT NULL;
CREATE UNIQUE INDEX idx_vex_statements_scope ON vex_statements USING btree (org_id, advisory_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(component_purl, ''::text));
ALTER TABLE vex_statements DROP COLUMN superseded_at;
ALTER TABLE vex_statements
    DROP CONSTRAINT vex_product_axis_needs_repo,
    DROP CONSTRAINT vex_product_axis_single,
    DROP COLUMN approved_at,
    DROP COLUMN approved_by,
    DROP COLUMN withdrawn,
    DROP COLUMN supersedes,
    DROP COLUMN evidence,
    DROP COLUMN version_range,
    DROP COLUMN release_id;
