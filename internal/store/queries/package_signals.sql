-- name: UpsertPackageSignals :exec
-- One statement per batch (same unnest batching as kev.sql). Timestamps
-- travel as text with '' meaning NULL, because sqlc's timestamptz[] binding
-- cannot carry NULLs; alternatives and raw travel as JSON text per row.
INSERT INTO package_signals (
    purl, system, name, version, published_at, cooldown_end,
    deprecated, deprecated_reason, low_usage, alternatives, not_found,
    malicious, vulnerable_critical, recommended_version, raw, fetched_at
)
SELECT unnest(sqlc.arg(purls)::text[]),
       unnest(sqlc.arg(systems)::text[]),
       unnest(sqlc.arg(names)::text[]),
       unnest(sqlc.arg(versions)::text[]),
       nullif(unnest(sqlc.arg(published_ats)::text[]), '')::timestamptz,
       nullif(unnest(sqlc.arg(cooldown_ends)::text[]), '')::timestamptz,
       unnest(sqlc.arg(deprecateds)::boolean[]),
       unnest(sqlc.arg(deprecated_reasons)::text[]),
       unnest(sqlc.arg(low_usages)::boolean[]),
       unnest(sqlc.arg(alternatives)::text[])::jsonb,
       unnest(sqlc.arg(not_founds)::boolean[]),
       unnest(sqlc.arg(maliciouses)::boolean[]),
       unnest(sqlc.arg(vulnerable_criticals)::boolean[]),
       unnest(sqlc.arg(recommended_versions)::text[]),
       unnest(sqlc.arg(raws)::text[])::jsonb,
       now()
ON CONFLICT (purl) DO UPDATE SET
    system = EXCLUDED.system,
    name = EXCLUDED.name,
    version = EXCLUDED.version,
    published_at = EXCLUDED.published_at,
    cooldown_end = EXCLUDED.cooldown_end,
    deprecated = EXCLUDED.deprecated,
    deprecated_reason = EXCLUDED.deprecated_reason,
    low_usage = EXCLUDED.low_usage,
    alternatives = EXCLUDED.alternatives,
    not_found = EXCLUDED.not_found,
    malicious = EXCLUDED.malicious,
    vulnerable_critical = EXCLUDED.vulnerable_critical,
    recommended_version = EXCLUDED.recommended_version,
    raw = EXCLUDED.raw,
    fetched_at = now();

-- name: GetPackageSignalsByPurls :many
SELECT * FROM package_signals WHERE purl = ANY(sqlc.arg(purls)::text[]);

-- name: ListPackageSignalFreshness :many
-- purl and fetched_at only: the sync decides which of a candidate set still
-- need a lookup without pulling every row's payload.
SELECT purl, fetched_at FROM package_signals WHERE purl = ANY(sqlc.arg(purls)::text[]);

-- name: CountPackageSignals :one
SELECT count(*)::bigint FROM package_signals;

-- name: PurgeAllPackageSignals :exec
-- Disabled means disabled (same stance as the KEV purge): stale rows would
-- otherwise show cooldown and deprecation states nobody refreshes.
DELETE FROM package_signals;

-- name: ListDistinctComponentPurlsBySnapshots :many
-- The candidate set for one sync chunk: every distinct purl in the given
-- snapshots. The caller chunks snapshot ids and filters by system.
SELECT DISTINCT c.purl
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
WHERE sc.snapshot_id = ANY(sqlc.arg(snapshot_ids)::uuid[])
	-- A lockfile that resolved the package from somewhere other than the
	-- public registry marks it private (ADR-048 §4): its name never leaves.
	AND NOT (sc.labels ? 'registry:private');
