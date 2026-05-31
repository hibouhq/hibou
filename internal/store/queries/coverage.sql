-- name: CreateCoverageReport :one
INSERT INTO coverage_reports (snapshot_id, format, line_rate, branch_rate, lines_valid, lines_covered, branches_valid, branches_covered)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetCoverageReportBySnapshot :one
SELECT * FROM coverage_reports WHERE snapshot_id = $1;

-- name: CreateCoverageFile :one
INSERT INTO coverage_files (coverage_report_id, file_path, line_rate, branch_rate, lines_valid, lines_covered, branches_valid, branches_covered)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListCoverageFilesByReport :many
SELECT * FROM coverage_files WHERE coverage_report_id = $1 ORDER BY file_path;

-- name: GetLatestCoverageByRef :one
SELECT cr.* FROM coverage_reports cr
JOIN snapshots s ON s.id = cr.snapshot_id
WHERE s.ref_id = $1
  AND s.status != 'purged'
ORDER BY s.created_at DESC
LIMIT 1;

-- name: ListCoverageFilesBySnapshot :many
SELECT cf.* FROM coverage_files cf
JOIN coverage_reports cr ON cr.id = cf.coverage_report_id
WHERE cr.snapshot_id = $1
ORDER BY cf.file_path;
