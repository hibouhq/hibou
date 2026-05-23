-- name: GetAdvisoryCache :one
SELECT * FROM advisory_cache
WHERE ecosystem = $1 AND package_name = $2 AND provider = $3 AND expires_at > NOW();

-- name: UpsertAdvisoryCache :exec
INSERT INTO advisory_cache (ecosystem, package_name, provider, response_data, advisory_count, fetched_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (ecosystem, package_name, provider) DO UPDATE SET
    response_data = EXCLUDED.response_data,
    advisory_count = EXCLUDED.advisory_count,
    fetched_at = EXCLUDED.fetched_at,
    expires_at = EXCLUDED.expires_at;

-- name: DeleteExpiredAdvisoryCache :exec
DELETE FROM advisory_cache WHERE expires_at < NOW();

-- name: InvalidateAdvisoryCacheByPackage :exec
DELETE FROM advisory_cache WHERE ecosystem = $1 AND package_name = $2;

-- name: InvalidateAdvisoryCacheByProvider :exec
DELETE FROM advisory_cache WHERE provider = $1;