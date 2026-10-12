-- name: ListAdvisoryProviderStats :many
SELECT
    sp.provider,
    MAX(sp.completed_at) AS last_completed_at,
    COALESCE(SUM(sp.advisories_found), 0)::bigint AS total_advisories,
    COUNT(DISTINCT s.repo_id)::bigint AS repo_count,
    MAX(CASE WHEN sp.status = 'failed' THEN sp.completed_at END) AS last_error_at,
    (
        ARRAY_AGG(NULLIF(sp.error_message, '') ORDER BY sp.completed_at DESC)
        FILTER (WHERE sp.status = 'failed' AND sp.error_message <> '')
    )[1] AS last_error
FROM scan_providers sp
JOIN scans sc ON sc.id = sp.scan_id
JOIN snapshots s ON s.id = sc.snapshot_id
WHERE s.org_id = $1
GROUP BY sp.provider
ORDER BY sp.provider;

-- name: ListFindingToolStats :many
SELECT
        v.scanner_name AS tool,
        MAX(v.last_seen_at) AS last_seen_at,
    COUNT(*)::bigint AS finding_count,
    COUNT(DISTINCT v.repo_id)::bigint AS repo_count
FROM vulnerabilities v
WHERE v.org_id = $1
    AND v.type != 'dependency'
    AND v.type != 'malware'
GROUP BY v.scanner_name
ORDER BY v.scanner_name;

-- name: ListVEXSourceStats :many
SELECT
    vs.source::text AS source,
    MAX(vs.created_at) AS last_seen_at,
    COUNT(*)::bigint AS statement_count,
    COUNT(DISTINCT vs.repo_id)::bigint AS repo_count
FROM vex_statements vs
WHERE vs.org_id = $1
GROUP BY vs.source
ORDER BY vs.source::text;

-- name: ListComponentEcosystemStats :many
WITH latest_repo_snapshots AS (
    SELECT DISTINCT ON (s.repo_id)
        s.id AS snapshot_id,
        s.repo_id
    FROM snapshots s
    WHERE s.org_id = $1
    ORDER BY s.repo_id, s.created_at DESC, s.id DESC
)
SELECT
    c.ecosystem,
    COUNT(DISTINCT c.id)::bigint AS component_count,
    COUNT(DISTINCT lrs.repo_id)::bigint AS repo_count,
    MAX(s.created_at) AS last_seen_at
FROM latest_repo_snapshots lrs
JOIN snapshot_components sc ON sc.snapshot_id = lrs.snapshot_id
JOIN components c ON c.id = sc.component_id
JOIN snapshots s ON s.id = lrs.snapshot_id
GROUP BY c.ecosystem
ORDER BY c.ecosystem;

-- name: ListCoverageSnapshotStats :many
SELECT
        COALESCE(NULLIF(TRIM(cr.format), ''), 'unknown') AS format,
    MAX(s.created_at) AS last_seen_at,
    COUNT(*)::bigint AS snapshot_count,
    COUNT(DISTINCT s.repo_id)::bigint AS repo_count
FROM snapshots s
JOIN coverage_reports cr ON cr.snapshot_id = s.id
WHERE s.org_id = $1
    AND LOWER(COALESCE(cr.format, '')) IN ('cobertura', 'jacoco', 'clover', 'lcov', 'gocover')
GROUP BY COALESCE(NULLIF(TRIM(cr.format), ''), 'unknown')
ORDER BY COALESCE(NULLIF(TRIM(cr.format), ''), 'unknown');

-- name: ListProducerRunToolStats :many
-- Per producer: when it last ran, its latest outcome, and its last failure
-- (ADR-034 §2). Feeds the tool catalog's health and "latest run partial or
-- failed" warning.
SELECT
    pr.producer,
    MAX(pr.created_at) AS last_run_at,
    MAX(pr.created_at) FILTER (WHERE pr.outcome = 'completed') AS last_success_at,
    MAX(pr.created_at) FILTER (WHERE pr.outcome = 'failed') AS last_error_at,
    COALESCE((ARRAY_AGG(pr.detail ORDER BY pr.created_at DESC)
        FILTER (WHERE pr.outcome = 'failed' AND pr.detail IS NOT NULL))[1], '')::text AS last_error,
    COALESCE((ARRAY_AGG(pr.outcome::text ORDER BY pr.created_at DESC))[1], '')::text AS last_outcome,
    COUNT(*)::bigint AS run_count,
    COUNT(DISTINCT s.repo_id)::bigint AS repo_count
FROM producer_runs pr
JOIN snapshots s ON s.id = pr.snapshot_id
WHERE s.org_id = $1
GROUP BY pr.producer
ORDER BY pr.producer;
