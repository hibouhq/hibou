-- +goose Up
-- A merge waiting for a second person under the four-eyes setting
-- (ADR-053 §3), kept on the incident that would be absorbed.
ALTER TABLE incidents ADD COLUMN proposed_merge jsonb NOT NULL DEFAULT 'null'::jsonb;
