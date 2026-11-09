-- +goose Up
-- ADR-053: one optional external reference per incident (a ticket key, a
-- link) instead of one per completed action; and the organisation's autolink
-- references, which turn "SEC-7" into a link wherever people write.
ALTER TABLE incidents ADD COLUMN external_ref text NOT NULL DEFAULT '';

CREATE TABLE org_autolinks (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    prefix       text NOT NULL,
    -- url_template holds <num> where the matched reference goes.
    url_template text NOT NULL,
    -- alphanumeric: the reference after the prefix matches [A-Za-z0-9-]+;
    -- otherwise digits only.
    alphanumeric boolean NOT NULL DEFAULT true,
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, prefix)
);
