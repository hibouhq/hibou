-- name: UpsertRelease :one
-- Release identity is (repo_id, version): API/CLI creates and forge release
-- webhooks converge on the same row (ADR-024 §5). Later writers fill what the
-- earlier one couldn't know without clobbering it — empty JSON payloads and
-- NULLs keep the stored value, and the row keeps the source that created it.
INSERT INTO releases (repo_id, ref_id, snapshot_id, version, build_metadata, artifact_ids, provenance, published_at, html_url, source)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (repo_id, version) DO UPDATE SET
    ref_id = EXCLUDED.ref_id,
    snapshot_id = COALESCE(EXCLUDED.snapshot_id, releases.snapshot_id),
    build_metadata = CASE WHEN EXCLUDED.build_metadata = '{}'::jsonb THEN releases.build_metadata ELSE EXCLUDED.build_metadata END,
    artifact_ids = CASE WHEN EXCLUDED.artifact_ids = '[]'::jsonb THEN releases.artifact_ids ELSE EXCLUDED.artifact_ids END,
    provenance = CASE WHEN EXCLUDED.provenance = '{}'::jsonb THEN releases.provenance ELSE EXCLUDED.provenance END,
    published_at = COALESCE(EXCLUDED.published_at, releases.published_at),
    html_url = COALESCE(EXCLUDED.html_url, releases.html_url),
    updated_at = NOW()
RETURNING *;

-- name: GetReleaseByID :one
SELECT * FROM releases WHERE id = $1;

-- name: GetReleaseByRepoAndID :one
SELECT * FROM releases WHERE repo_id = $1 AND id = $2;

-- name: ListReleasesByRepo :many
SELECT * FROM releases WHERE repo_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: CountReleasesByRepo :one
SELECT COUNT(*)::bigint FROM releases WHERE repo_id = $1;

-- name: ListReleasesWithRiskByRepo :many
-- Enriched listing for the Releases tab: per release, the open-risk severity
-- counts of its pinned snapshot (platform-wide semantics: resolved and ordinary
-- suppressions out, active false-positive acceptances out — ADR-023), the clients currently
-- on it via active deployments, and the snapshot's last completed scan.
SELECT
    rel.*,
    ref.name AS ref_name,
    COALESCE(risk.critical_count, 0)::bigint AS critical_count,
    COALESCE(risk.high_count, 0)::bigint AS high_count,
    COALESCE(risk.medium_count, 0)::bigint AS medium_count,
    COALESCE(risk.low_count, 0)::bigint AS low_count,
    COALESCE(risk.kev_open, 0)::bigint AS kev_open,
    COALESCE(risk.total_count, 0)::bigint AS open_finding_count,
    COALESCE(scan.last_scanned_at, '1970-01-01T00:00:00Z'::timestamptz)::timestamptz AS last_scanned_at,
    COALESCE(dep.clients, '[]'::jsonb) AS clients,
    snap.commit_sha AS commit_sha,
    pending_snap.commit_sha AS pending_commit_sha
FROM releases rel
JOIN refs ref ON ref.id = rel.ref_id
LEFT JOIN snapshots snap ON snap.id = rel.snapshot_id
LEFT JOIN snapshots pending_snap ON pending_snap.id = rel.pending_snapshot_id
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) FILTER (WHERE v.severity = 'critical') AS critical_count,
        COUNT(*) FILTER (WHERE v.severity = 'high') AS high_count,
        COUNT(*) FILTER (WHERE v.severity = 'medium') AS medium_count,
        COUNT(*) FILTER (WHERE v.severity = 'low') AS low_count,
        COUNT(*) FILTER (WHERE v.type IN ('dependency', 'container', 'malware') AND (
            EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))
            OR EXISTS (
                SELECT 1 FROM advisories adv
                LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id
                JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))
                WHERE adv.id = v.advisory_id
            )
        )) AS kev_open,
        COUNT(*) AS total_count
    FROM vulnerabilities v
    LEFT JOIN finding_acceptances fa
      ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
      AND (fa.expires_at IS NULL OR fa.expires_at > now())
    LEFT JOIN finding_disputes fd
      ON fd.repo_id = v.repo_id AND fd.fingerprint = v.fingerprint
    WHERE v.snapshot_id = rel.snapshot_id
      AND v.status != 'resolved'
      AND (v.status != 'suppressed' OR fd.fingerprint IS NOT NULL)
      AND COALESCE(fa.reason_kind::text, '') != 'false_positive'
) risk ON true
LEFT JOIN LATERAL (
    SELECT MAX(sc.completed_at) AS last_scanned_at
    FROM scans sc
    WHERE sc.snapshot_id = rel.snapshot_id AND sc.status = 'complete'
) scan ON true
LEFT JOIN LATERAL (
    SELECT jsonb_agg(jsonb_build_object(
        'deployment_id', d.id,
        'client_id', c.id,
        'slug', c.slug,
        'name', c.name,
        'environment', d.environment,
        'deployed_at', d.deployed_at
    ) ORDER BY c.name, d.environment) AS clients
    FROM deployments d
    JOIN clients c ON c.id = d.client_id
    WHERE d.release_id = rel.id AND d.status = 'active'
) dep ON true
WHERE rel.repo_id = sqlc.arg(repo_id)
  AND (sqlc.arg(version_query)::text = '' OR position(lower(sqlc.arg(version_query)) IN lower(rel.version)) > 0)
  AND (sqlc.arg(client_slug)::text = '' OR EXISTS (
    SELECT 1 FROM deployments d2
    JOIN clients c2 ON c2.id = d2.client_id
    WHERE d2.release_id = rel.id AND d2.status = 'active' AND c2.slug = sqlc.arg(client_slug)
  ))
  AND (NOT sqlc.arg(vulnerable_only)::boolean OR COALESCE(risk.total_count, 0) > 0)
ORDER BY rel.created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountReleasesWithRiskByRepo :one
SELECT COUNT(*)::bigint
FROM releases rel
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS total_count
    FROM vulnerabilities v
    LEFT JOIN finding_acceptances fa
      ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
      AND (fa.expires_at IS NULL OR fa.expires_at > now())
    LEFT JOIN finding_disputes fd
      ON fd.repo_id = v.repo_id AND fd.fingerprint = v.fingerprint
    WHERE v.snapshot_id = rel.snapshot_id
      AND v.status != 'resolved'
      AND (v.status != 'suppressed' OR fd.fingerprint IS NOT NULL)
      AND COALESCE(fa.reason_kind::text, '') != 'false_positive'
) risk ON true
WHERE rel.repo_id = sqlc.arg(repo_id)
  AND (sqlc.arg(version_query)::text = '' OR position(lower(sqlc.arg(version_query)) IN lower(rel.version)) > 0)
  AND (sqlc.arg(client_slug)::text = '' OR EXISTS (
    SELECT 1 FROM deployments d2
    JOIN clients c2 ON c2.id = d2.client_id
    WHERE d2.release_id = rel.id AND d2.status = 'active' AND c2.slug = sqlc.arg(client_slug)
  ))
  AND (NOT sqlc.arg(vulnerable_only)::boolean OR COALESCE(risk.total_count, 0) > 0);

-- name: ListReleasesByOrg :many
SELECT r.* FROM releases r
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1
ORDER BY r.created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountReleasesByOrg :one
SELECT COUNT(*)::bigint FROM releases r
JOIN repositories repo ON repo.id = r.repo_id
WHERE repo.org_id = $1;

-- name: CountReleasesBySnapshotExcluding :one
-- Snapshot unpin guard: how many *other* releases still pin this snapshot.
SELECT COUNT(*)::bigint FROM releases WHERE snapshot_id = $1 AND id <> $2;

-- name: ListReleasePinnedSnapshotIDs :many
-- Distinct snapshots referenced by any release, oldest-scanned first, for the
-- advisory refresh worker (ADR-024 §6).
SELECT DISTINCT rel.snapshot_id
FROM releases rel
WHERE rel.snapshot_id IS NOT NULL;

-- name: GetReleaseByRepoVersion :one
SELECT * FROM releases WHERE repo_id = $1 AND version = $2;

-- name: SetReleaseSnapshot :one
-- Repoint a release to a snapshot (initial derivation refresh, or a release
-- manager adopting a re-tagged build). Clears any pending divergence.
UPDATE releases
SET snapshot_id = $2,
    pending_snapshot_id = NULL,
    diverged_at = NULL,
    dismissed_commit_sha = NULL,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetReleaseDivergence :one
-- The tag was recreated on another commit while clients run this release:
-- record the candidate and surface it instead of silently repointing.
UPDATE releases
SET pending_snapshot_id = $2,
    diverged_at = NOW(),
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DismissReleaseDivergence :one
-- "Keep old build": clear the divergence and remember the dismissed commit so
-- the same candidate does not re-flag on the next scan of that tag.
UPDATE releases
SET pending_snapshot_id = NULL,
    diverged_at = NULL,
    dismissed_commit_sha = $2,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteRelease :exec
DELETE FROM releases WHERE id = $1;

-- name: AttachSnapshotToReleasesByRef :execrows
-- Closes the webhook-before-upload race (ADR-024 §5): when a tag ref's
-- analysis lands after the forge release event, adopt it on the snapshot-less
-- releases of that ref.
UPDATE releases SET snapshot_id = $2, updated_at = NOW()
WHERE ref_id = $1 AND snapshot_id IS NULL;
