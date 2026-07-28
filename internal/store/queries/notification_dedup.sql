-- name: MarkNotificationSent :execrows
-- Returns 1 when this is the first notification for the pair (so the caller
-- should notify), 0 when it was already sent.
INSERT INTO notification_dedup (event_type, repo_id)
VALUES ($1, $2)
ON CONFLICT (event_type, repo_id) DO NOTHING;

-- name: DeleteResolvedNotifications :exec
-- Forgets repos that are no longer in the offending set, so a repo that becomes
-- stale again is notified again.
DELETE FROM notification_dedup
WHERE event_type = $1
  AND NOT (repo_id = ANY(sqlc.arg(active_repo_ids)::uuid[]));
