-- name: CreateScanPlan :one
INSERT INTO scan_plans (repo_id, ref_name, commit_sha, base_commit_sha, mode, digest, detection_revision, catalog_revision, plan, created_by_api_key_id)
VALUES ($1, $2, $3, sqlc.narg(base_commit_sha), $4, $5, $6, $7, $8, sqlc.narg(created_by_api_key_id))
RETURNING *;

-- name: GetScanPlan :one
SELECT * FROM scan_plans WHERE id = $1 AND repo_id = $2;

-- name: GetLatestScanPlan :one
SELECT * FROM scan_plans WHERE repo_id = $1 ORDER BY created_at DESC LIMIT 1;

-- name: SetSnapshotArtifactPlanJob :exec
UPDATE snapshot_artifacts SET plan_id = $2, plan_job_id = $3 WHERE id = $1;

-- name: SetProducerRunsPlanJob :exec
UPDATE producer_runs SET plan_id = $2, plan_job_id = $3 WHERE artifact_id = $1;
