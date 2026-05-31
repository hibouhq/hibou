-- name: CreateNotificationRule :one
INSERT INTO notification_rules (org_id, name, event_type, conditions, destination_type, destination_config, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetNotificationRuleByID :one
SELECT * FROM notification_rules WHERE id = $1;

-- name: ListNotificationRulesByOrg :many
SELECT * FROM notification_rules WHERE org_id = $1 ORDER BY name;

-- name: ListEnabledRulesByOrgAndEventType :many
SELECT * FROM notification_rules WHERE org_id = $1 AND event_type = $2 AND enabled = TRUE ORDER BY name;

-- name: UpdateNotificationRule :one
UPDATE notification_rules SET name = $2, event_type = $3, conditions = $4, destination_type = $5, destination_config = $6, enabled = $7, updated_at = NOW()
WHERE id = $1 RETURNING *;

-- name: DeleteNotificationRule :exec
DELETE FROM notification_rules WHERE id = $1;
