-- name: SetSnapshotArtifactRunDeclaration :exec
UPDATE snapshot_artifacts
SET scope = sqlc.narg(scope),
    scope_paths = sqlc.arg(scope_paths)::text[],
    tool_version = sqlc.narg(tool_version),
    config_digest = sqlc.narg(config_digest)
WHERE id = sqlc.arg(id);

-- name: DeleteProducerRunsByArtifact :exec
DELETE FROM producer_runs WHERE artifact_id = $1;

-- name: CreateArtifactProducerRun :one
INSERT INTO producer_runs (
    snapshot_id, artifact_id, run_index, producer, version, config_digest,
    scope, scope_declared, scope_paths, outcome, skipped_files, finding_count, detail
) VALUES (
    sqlc.arg(snapshot_id), sqlc.arg(artifact_id), sqlc.arg(run_index), sqlc.arg(producer),
    sqlc.narg(version), sqlc.narg(config_digest), sqlc.arg(scope), sqlc.arg(scope_declared),
    sqlc.arg(scope_paths)::text[], sqlc.arg(outcome), sqlc.arg(skipped_files), sqlc.arg(finding_count),
    sqlc.narg(detail)
)
ON CONFLICT (artifact_id, run_index) WHERE artifact_id IS NOT NULL DO UPDATE SET
    producer = EXCLUDED.producer,
    version = EXCLUDED.version,
    config_digest = EXCLUDED.config_digest,
    scope = EXCLUDED.scope,
    scope_declared = EXCLUDED.scope_declared,
    scope_paths = EXCLUDED.scope_paths,
    outcome = EXCLUDED.outcome,
    skipped_files = EXCLUDED.skipped_files,
    finding_count = EXCLUDED.finding_count,
    detail = EXCLUDED.detail
RETURNING *;

-- name: UpsertSnapshotProducerRun :one
INSERT INTO producer_runs (
    snapshot_id, producer, version, config_digest,
    scope, scope_declared, scope_paths, outcome, skipped_files, finding_count, detail
) VALUES (
    sqlc.arg(snapshot_id), sqlc.arg(producer), sqlc.narg(version), sqlc.narg(config_digest),
    sqlc.arg(scope), sqlc.arg(scope_declared), sqlc.arg(scope_paths)::text[], sqlc.arg(outcome),
    sqlc.arg(skipped_files), sqlc.arg(finding_count), sqlc.narg(detail)
)
ON CONFLICT (snapshot_id, producer) WHERE artifact_id IS NULL DO UPDATE SET
    version = EXCLUDED.version,
    config_digest = EXCLUDED.config_digest,
    scope = EXCLUDED.scope,
    scope_declared = EXCLUDED.scope_declared,
    scope_paths = EXCLUDED.scope_paths,
    outcome = EXCLUDED.outcome,
    skipped_files = EXCLUDED.skipped_files,
    finding_count = EXCLUDED.finding_count,
    detail = EXCLUDED.detail
RETURNING *;

-- name: ListProducerRunsBySnapshot :many
SELECT * FROM producer_runs
WHERE snapshot_id = $1
ORDER BY producer, created_at, run_index;

-- name: GetPreviousCompleteSnapshotByRef :one
-- The predecessor a snapshot's coverage is compared with (ADR-034, D2): the
-- latest finished snapshot of the same ref created before it.
SELECT * FROM snapshots
WHERE ref_id = sqlc.arg(ref_id)
  AND id <> sqlc.arg(snapshot_id)
  AND status IN ('complete', 'active')
  AND created_at < sqlc.arg(created_at)
ORDER BY created_at DESC
LIMIT 1;

-- name: SnapshotCoverageKnown :one
-- False for a snapshot processed before producer runs were recorded: it has
-- SARIF artifacts but no runs, so its coverage is unknown and the old
-- "absent = resolved" reading must stay for it.
SELECT (
    EXISTS (SELECT 1 FROM producer_runs pr WHERE pr.snapshot_id = $1)
    OR NOT EXISTS (SELECT 1 FROM snapshot_artifacts sa WHERE sa.snapshot_id = $1 AND sa.kind = 'sarif')
)::boolean AS known;
