-- ADR-038 §2: every rating a source publishes, and the one each finding uses.

-- name: SyncAdvisorySourceRatings :exec
-- Replaces one source's ratings with the given set, touching only rows that
-- changed: a provider refresh that brings the same ratings writes nothing.
-- Parallel arrays; '' stands for NULL in versions, scores and labels.
WITH incoming AS (
    SELECT t.rater,
           NULLIF(t.version, '')::cvss_version AS cvss_version,
           t.vector AS cvss_vector,
           NULLIF(t.score, '')::numeric(4,2) AS cvss_score,
           NULLIF(t.label, '')::severity_level AS label
      FROM (SELECT unnest(sqlc.arg(raters)::text[]) AS rater,
                   unnest(sqlc.arg(versions)::text[]) AS version,
                   unnest(sqlc.arg(vectors)::text[]) AS vector,
                   unnest(sqlc.arg(scores)::text[]) AS score,
                   unnest(sqlc.arg(labels)::text[]) AS label) t
), removed AS (
    DELETE FROM advisory_ratings r
     WHERE r.advisory_source_id = sqlc.arg(advisory_source_id)
       AND NOT EXISTS (SELECT 1 FROM incoming i
                        WHERE i.rater = r.rater AND i.cvss_version IS NOT DISTINCT FROM r.cvss_version)
)
INSERT INTO advisory_ratings (advisory_source_id, rater, cvss_version, cvss_vector, cvss_score, label)
SELECT sqlc.arg(advisory_source_id), rater, cvss_version, cvss_vector, cvss_score, label FROM incoming
ON CONFLICT ON CONSTRAINT advisory_ratings_key DO UPDATE SET
    cvss_vector = EXCLUDED.cvss_vector,
    cvss_score = EXCLUDED.cvss_score,
    label = EXCLUDED.label
WHERE (advisory_ratings.cvss_vector, advisory_ratings.cvss_score, advisory_ratings.label)
      IS DISTINCT FROM (EXCLUDED.cvss_vector, EXCLUDED.cvss_score, EXCLUDED.label);

-- name: ListAdvisoryRatings :many
SELECT s.advisory_id, s.provider, r.rater, r.cvss_version, r.cvss_vector, r.cvss_score, r.label
  FROM advisory_ratings r
  JOIN advisory_sources s ON s.id = r.advisory_source_id
 WHERE s.advisory_id = ANY(sqlc.arg(advisory_ids)::uuid[])
 ORDER BY s.advisory_id, r.rater, r.cvss_version;

-- name: ListAdvisorySourcesForRatings :many
-- Sources whose ratings were built by an older mapping, oldest first: the
-- startup backfill rebuilds them from raw_data in batches.
SELECT id, advisory_id, provider, provider_id, raw_data
  FROM advisory_sources
 WHERE ratings_version < sqlc.arg(ratings_version)
 ORDER BY id
 LIMIT sqlc.arg(batch_size);

-- name: SetAdvisorySourceRatingsVersion :exec
UPDATE advisory_sources SET ratings_version = sqlc.arg(ratings_version) WHERE id = sqlc.arg(id);

-- name: ListFindingsForRating :many
-- Every finding of these advisories, current and historical snapshots alike:
-- a rating a finding copied must not go stale anywhere.
SELECT id, advisory_id, type, ecosystem, component_purl, severity, original_severity,
       (severity_override_by IS NOT NULL)::boolean AS overridden,
       cvss_score, cvss_version, cvss_vector, rated_by
  FROM vulnerabilities
 WHERE advisory_id = ANY(sqlc.arg(advisory_ids)::uuid[]);

-- name: SetFindingRating :exec
-- A manual override keeps its severity; the rating and original severity
-- still follow the data, so the override's "was" stays truthful.
UPDATE vulnerabilities
SET original_severity = sqlc.arg(severity),
    severity = CASE WHEN severity_override_by IS NULL THEN sqlc.arg(severity) ELSE severity END,
    cvss_score = sqlc.narg(cvss_score),
    cvss_version = sqlc.narg(cvss_version),
    cvss_vector = sqlc.arg(cvss_vector),
    rated_by = sqlc.arg(rated_by),
    updated_at = NOW()
WHERE id = sqlc.arg(id);

-- name: ListAdvisoriesWithStaleCVERating :many
-- Advisories whose CVE-feed rating (provider 'cve') differs from what the
-- feed holds now, or that have none while the feed rates one of their CVEs.
-- The reconcile pass re-rates exactly these (ADR-038 §2), so a CVE-feed sweep
-- reaches findings without the sweeper knowing about advisories. "best"
-- picks the record the way ListCVERatingsForAdvisory does, so an advisory
-- with two CVE aliases is not seen as stale forever.
WITH best AS (
    SELECT DISTINCT ON (al.advisory_id) al.advisory_id, r.cve_id, r.cvss_vector, r.severity, r.cvss_source
      FROM advisory_aliases al
      JOIN cve_records r ON r.cve_id = upper(al.alias)
     WHERE r.cvss_vector <> '' OR r.severity <> ''
     ORDER BY al.advisory_id, (r.cvss_vector <> '') DESC, r.cvss_score DESC NULLS LAST, r.cve_id
)
SELECT b.advisory_id
  FROM best b
  LEFT JOIN advisory_sources s ON s.advisory_id = b.advisory_id AND s.provider = 'cve'
 WHERE s.id IS NULL
    OR s.provider_id <> b.cve_id
    OR s.raw_data->>'vector' IS DISTINCT FROM b.cvss_vector
    OR s.raw_data->>'severity' IS DISTINCT FROM b.severity
    OR s.raw_data->>'source' IS DISTINCT FROM b.cvss_source
 LIMIT sqlc.arg(batch_size);

-- name: ListCVERatingsForAdvisory :many
-- The CVE-feed records behind one advisory, scored ones only, strongest
-- first (vector before label, newest record first).
SELECT r.cve_id, r.cvss_score, r.cvss_vector, r.severity, r.cvss_source
  FROM advisory_aliases al
  JOIN cve_records r ON r.cve_id = upper(al.alias)
 WHERE al.advisory_id = sqlc.arg(advisory_id)
   AND (r.cvss_vector <> '' OR r.severity <> '')
 ORDER BY (r.cvss_vector <> '') DESC, r.cvss_score DESC NULLS LAST, r.cve_id;

-- name: UpsertCVEAdvisorySource :one
INSERT INTO advisory_sources (advisory_id, provider, provider_id, raw_data, fetched_at, ratings_version)
VALUES (sqlc.arg(advisory_id), 'cve', sqlc.arg(provider_id), sqlc.arg(raw_data), NOW(), sqlc.arg(ratings_version))
ON CONFLICT (advisory_id, provider) DO UPDATE SET
    provider_id = EXCLUDED.provider_id,
    raw_data = EXCLUDED.raw_data,
    fetched_at = EXCLUDED.fetched_at,
    ratings_version = EXCLUDED.ratings_version
RETURNING id;

-- name: DeleteCVEAdvisorySource :exec
DELETE FROM advisory_sources WHERE advisory_id = sqlc.arg(advisory_id) AND provider = 'cve';

-- name: InsertEPSSScores :exec
-- One batch of the daily load; the sync clears and reloads in one
-- transaction, so readers see yesterday's scores or today's, never a mix.
INSERT INTO epss_scores (cve_id, score, percentile)
SELECT unnest(sqlc.arg(cve_ids)::text[]),
       unnest(sqlc.arg(scores)::numeric[]),
       unnest(sqlc.arg(percentiles)::numeric[])
ON CONFLICT (cve_id) DO UPDATE SET score = EXCLUDED.score, percentile = EXCLUDED.percentile;

-- name: ClearEPSSScores :exec
DELETE FROM epss_scores;

-- name: GetEPSSCatalog :one
SELECT * FROM epss_catalog WHERE id;

-- name: SetEPSSCatalog :exec
INSERT INTO epss_catalog (id, model_version, score_date, row_count, synced_at)
VALUES (TRUE, sqlc.arg(model_version), sqlc.arg(score_date), sqlc.arg(row_count), NOW())
ON CONFLICT (id) DO UPDATE SET
    model_version = EXCLUDED.model_version,
    score_date = EXCLUDED.score_date,
    row_count = EXCLUDED.row_count,
    synced_at = EXCLUDED.synced_at;

-- name: ListEPSSForAdvisories :many
-- A finding's EPSS is the highest score among its advisory's canonical ID and
-- CVE aliases (Dependency-Track's alias inheritance, ADR-038 §4).
-- The canonical ID and the aliases are unioned first so each probe is a
-- primary-key lookup.
SELECT DISTINCT ON (ids.advisory_id) ids.advisory_id, e.cve_id, e.score, e.percentile
  FROM (SELECT a.id AS advisory_id, upper(a.canonical_id) AS cve_id
          FROM advisories a WHERE a.id = ANY(sqlc.arg(advisory_ids)::uuid[])
        UNION
        SELECT al.advisory_id, upper(al.alias)
          FROM advisory_aliases al WHERE al.advisory_id = ANY(sqlc.arg(advisory_ids)::uuid[])) ids
  JOIN epss_scores e ON e.cve_id = ids.cve_id
 ORDER BY ids.advisory_id, e.score DESC;
