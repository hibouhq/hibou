-- +goose Down
DROP TABLE IF EXISTS org_autolinks;
ALTER TABLE incidents DROP COLUMN IF EXISTS external_ref;
