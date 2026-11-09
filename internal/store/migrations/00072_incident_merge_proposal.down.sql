-- +goose Down
ALTER TABLE incidents DROP COLUMN proposed_merge;
