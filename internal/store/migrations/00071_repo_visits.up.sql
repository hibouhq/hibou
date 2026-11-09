-- +goose Up
-- Repositories a person opens, for Home's "Your repositories" (ADR-053 §9):
-- ranked by how often and how recently, like a forge's top repositories.
-- A visit counts once per 30 minutes; page reloads do not inflate it.
CREATE TABLE user_repo_visits (
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_id         uuid        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    visit_count     integer     NOT NULL DEFAULT 1,
    last_visited_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, repo_id)
);
CREATE INDEX idx_user_repo_visits_recent ON user_repo_visits (user_id, last_visited_at DESC);
