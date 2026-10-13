-- name: CountPendingDeviceAuthorizationsByIP :one
SELECT COUNT(*)::int
FROM device_authorizations
WHERE requester_ip = $1 AND status = 'pending' AND expires_at > NOW();

-- name: CreateDeviceAuthorization :one
INSERT INTO device_authorizations (device_code_hash, user_code_hash, client_id, client_name, requested_preset, requester_ip, requester_user_agent, poll_interval_seconds, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetLiveDeviceAuthorizationByUserCode :one
SELECT *
FROM device_authorizations
WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > NOW();

-- name: PollDeviceAuthorization :one
-- Records the poll and applies RFC 8628 §3.5 slow_down: a poll that arrives
-- sooner than the current interval (one second of jitter allowed) raises the
-- interval by five seconds. prev_interval lets the caller tell it happened.
UPDATE device_authorizations d
SET last_polled_at = NOW(),
    poll_interval_seconds = CASE
        WHEN p.prev_polled_at IS NOT NULL
         AND p.prev_polled_at > NOW() - make_interval(secs => GREATEST(p.prev_interval - 1, 0))
        THEN p.prev_interval + 5
        ELSE p.prev_interval
    END
FROM (
    SELECT da.id, da.last_polled_at AS prev_polled_at, da.poll_interval_seconds AS prev_interval
    FROM device_authorizations da
    WHERE da.device_code_hash = $1
    FOR UPDATE
) p
WHERE d.id = p.id
RETURNING d.*, p.prev_interval::int AS prev_interval;

-- name: ApproveDeviceAuthorization :one
-- The approval keeps the row alive two more minutes, so a code approved in
-- its last seconds can still be collected by the next poll.
UPDATE device_authorizations
SET status = 'approved', approved_by = $2, approved_preset = $3, token_expires_at = $4,
    decided_at = NOW(), expires_at = GREATEST(expires_at, NOW() + INTERVAL '2 minutes')
WHERE id = $1 AND status = 'pending' AND expires_at > NOW()
RETURNING *;

-- name: DenyDeviceAuthorization :one
UPDATE device_authorizations
SET status = 'denied', approved_by = $2, decided_at = NOW()
WHERE id = $1 AND status = 'pending' AND expires_at > NOW()
RETURNING *;

-- name: ConsumeDeviceAuthorization :one
-- One successful exchange per approval: the row moves to consumed in the same
-- transaction that mints the key, so a replayed device_code gets expired_token.
UPDATE device_authorizations
SET status = 'consumed'
WHERE id = $1 AND status = 'approved' AND expires_at > NOW()
RETURNING *;

-- name: SetDeviceAuthorizationAPIKey :exec
UPDATE device_authorizations
SET api_key_id = $2
WHERE id = $1;

-- name: DeleteExpiredDeviceAuthorizations :execrows
-- Rows are kept an hour past expiry so a late poll still gets expired_token
-- rather than a generic invalid_grant.
DELETE FROM device_authorizations
WHERE expires_at < NOW() - INTERVAL '1 hour';
