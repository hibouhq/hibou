-- name: CreateNotification :one
INSERT INTO notifications (user_id, type, title, body, link, severity)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListNotificationsByUser :many
SELECT * FROM notifications WHERE user_id = $1
ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: CountUnreadNotifications :one
SELECT COUNT(*)::bigint FROM notifications WHERE user_id = $1 AND status = 'unread';

-- name: MarkNotificationRead :exec
UPDATE notifications SET status = 'read' WHERE id = $1 AND user_id = $2;

-- name: MarkAllNotificationsRead :exec
UPDATE notifications SET status = 'read' WHERE user_id = $1 AND status = 'unread';