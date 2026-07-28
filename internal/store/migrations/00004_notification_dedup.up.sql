-- Durable dedup for repeating, user-visible notifications (stale-scan today).
-- Previously an in-memory map, which re-notified every repo after a pod restart
-- and duplicated alerts once more than one replica ran the loop.
CREATE TABLE notification_dedup (
    event_type text NOT NULL,
    repo_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    notified_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (event_type, repo_id)
);
