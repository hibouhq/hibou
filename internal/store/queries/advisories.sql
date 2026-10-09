-- name: UpsertAdvisory :one
INSERT INTO advisories (canonical_id, title, description, severity, cvss_score, cvss_version, cvss_vector, is_malware, malware_type, published_at, withdrawn_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (canonical_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    severity = EXCLUDED.severity,
    cvss_score = EXCLUDED.cvss_score,
    cvss_version = EXCLUDED.cvss_version,
    cvss_vector = EXCLUDED.cvss_vector,
    is_malware = EXCLUDED.is_malware,
    malware_type = EXCLUDED.malware_type,
    published_at = EXCLUDED.published_at,
    withdrawn_at = EXCLUDED.withdrawn_at,
    updated_at = NOW()
RETURNING *;

-- name: UpdateAdvisoryCanonicalID :exec
UPDATE advisories
SET canonical_id = sqlc.arg(canonical_id), updated_at = NOW()
WHERE id = sqlc.arg(advisory_id);

-- name: GetAdvisoryByCanonicalID :one
SELECT * FROM advisories WHERE canonical_id = $1;

-- name: GetAdvisoryByID :one
SELECT * FROM advisories WHERE id = $1;

-- name: GetAdvisoriesByIDs :many
SELECT * FROM advisories WHERE id = ANY($1::uuid[]);

-- name: GetComponentByID :one
SELECT * FROM components WHERE id = $1;

-- name: GetComponentsByIDs :many
SELECT * FROM components WHERE id = ANY($1::uuid[]);

-- name: GetAdvisoryByAlias :one
SELECT a.* FROM advisories a
JOIN advisory_aliases aa ON aa.advisory_id = a.id
WHERE aa.alias = $1;

-- name: ListAdvisoriesByPackage :many
SELECT DISTINCT a.* FROM advisories a
JOIN affected_ranges ar ON ar.advisory_id = a.id
WHERE ar.ecosystem = $1 AND ar.package_name = $2
ORDER BY a.severity, a.created_at DESC;

-- name: UpsertAdvisoryAlias :exec
INSERT INTO advisory_aliases (advisory_id, alias)
VALUES ($1, $2)
ON CONFLICT (alias) DO NOTHING;

-- name: ListAliasesByAdvisory :many
SELECT * FROM advisory_aliases WHERE advisory_id = $1;

-- name: ListAliasesByAdvisoryIDs :many
SELECT * FROM advisory_aliases WHERE advisory_id = ANY($1::uuid[]);

-- name: GetAdvisoryIDByAlias :one
SELECT advisory_id FROM advisory_aliases WHERE alias = $1;

-- name: UpsertAdvisorySource :exec
INSERT INTO advisory_sources (advisory_id, provider, provider_id, severity, cvss_score, cvss_version, cvss_vector, raw_data, fetched_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (advisory_id, provider) DO UPDATE SET
    provider_id = EXCLUDED.provider_id,
    severity = EXCLUDED.severity,
    cvss_score = EXCLUDED.cvss_score,
    cvss_version = EXCLUDED.cvss_version,
    cvss_vector = EXCLUDED.cvss_vector,
    raw_data = EXCLUDED.raw_data,
    fetched_at = EXCLUDED.fetched_at;

-- name: ListSourcesByAdvisory :many
SELECT * FROM advisory_sources WHERE advisory_id = $1;

-- name: ListSourcesByAdvisoryIDs :many
SELECT * FROM advisory_sources WHERE advisory_id = ANY($1::uuid[]);

-- name: CreateAffectedRange :one
INSERT INTO affected_ranges (advisory_id, ecosystem, package_name, introduced, fixed, last_affected, source, release, vulnerable_symbols)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: ListAffectedRangesByAdvisory :many
SELECT * FROM affected_ranges WHERE advisory_id = $1;

-- name: ListAffectedRangesByAdvisoryIDs :many
SELECT * FROM affected_ranges WHERE advisory_id = ANY($1::uuid[]);

-- name: ListAffectedRangesByPackage :many
SELECT * FROM affected_ranges WHERE ecosystem = $1 AND package_name = $2;

-- name: DeleteAffectedRangesByAdvisoryAndSource :exec
DELETE FROM affected_ranges WHERE advisory_id = $1 AND source = $2;
