-- name: MarkNotificationSent :execrows
-- Returns 1 when this is the first notification for the pair (so the caller
-- should notify), 0 when it was already sent.
INSERT INTO notification_dedup (event_type, repo_id, identifier)
VALUES ($1, $2, '')
ON CONFLICT (event_type, repo_id, identifier) DO NOTHING;

-- name: DeleteResolvedNotifications :exec
-- Forgets repos that are no longer in the offending set, so a repo that becomes
-- stale again is notified again.
DELETE FROM notification_dedup
WHERE event_type = $1
  AND identifier = ''
  AND NOT (repo_id = ANY(sqlc.arg(active_repo_ids)::uuid[]));

-- name: MarkFindingsNotified :many
-- Batch dedup for per-finding notifications: inserts the identifiers not yet
-- on the ledger for this repo and returns only those — the set genuinely
-- worth notifying about. Already-known identifiers return nothing.
INSERT INTO notification_dedup (event_type, repo_id, identifier)
SELECT $1, $2, unnest(sqlc.arg(identifiers)::text[])
ON CONFLICT (event_type, repo_id, identifier) DO NOTHING
RETURNING identifier;

-- name: ClearFindingsNotified :exec
-- Forgets resolved findings so a regression re-notifies.
DELETE FROM notification_dedup
WHERE event_type = $1
  AND repo_id = $2
  AND identifier = ANY(sqlc.arg(identifiers)::text[]);
