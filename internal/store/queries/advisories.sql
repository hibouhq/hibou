-- name: UpsertAdvisory :one
-- Severity and CVSS are not written here: they are derived from the
-- advisory's ratings by SetAdvisoryRating once its sources are stored
-- (ADR-038 §2).
INSERT INTO advisories (canonical_id, title, description, is_malware, malware_type, published_at, withdrawn_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (canonical_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    is_malware = EXCLUDED.is_malware,
    malware_type = EXCLUDED.malware_type,
    published_at = EXCLUDED.published_at,
    withdrawn_at = EXCLUDED.withdrawn_at,
    updated_at = NOW()
RETURNING *;

-- name: SetAdvisoryRating :one
UPDATE advisories
SET severity = sqlc.arg(severity),
    cvss_score = sqlc.narg(cvss_score),
    cvss_version = sqlc.narg(cvss_version),
    cvss_vector = sqlc.arg(cvss_vector),
    rated_by = sqlc.arg(rated_by),
    updated_at = CASE
        WHEN (severity, cvss_score, cvss_version, cvss_vector, rated_by)
             IS DISTINCT FROM (sqlc.arg(severity), sqlc.narg(cvss_score)::numeric, sqlc.narg(cvss_version)::cvss_version, sqlc.arg(cvss_vector)::text, sqlc.arg(rated_by)::text)
        THEN NOW() ELSE updated_at END
WHERE id = sqlc.arg(advisory_id)
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

-- name: UpsertAdvisorySource :one
INSERT INTO advisory_sources (advisory_id, provider, provider_id, raw_data, fetched_at, ratings_version)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (advisory_id, provider) DO UPDATE SET
    provider_id = EXCLUDED.provider_id,
    raw_data = EXCLUDED.raw_data,
    fetched_at = EXCLUDED.fetched_at,
    ratings_version = EXCLUDED.ratings_version
RETURNING id;

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

-- name: ListAdvisoryIDsForExport :many
-- Keyset page of advisories with a range in the ecosystems, for the
-- offline advisory database (ADR-046 step 6). An empty list means every
-- ecosystem.
SELECT DISTINCT advisory_id FROM affected_ranges
WHERE (COALESCE(array_length(@ecosystems::text[], 1), 0) = 0 OR ecosystem = ANY(@ecosystems::text[]))
  AND advisory_id > @after_id
ORDER BY advisory_id
LIMIT @page_size;
