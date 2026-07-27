-- name: CreateCoverageReport :one
INSERT INTO coverage_reports (snapshot_id, format, line_rate, branch_rate, lines_valid, lines_covered, branches_valid, branches_covered)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetCoverageReportBySnapshotFormat :one
SELECT * FROM coverage_reports WHERE snapshot_id = $1 AND format = $2;

-- name: CreateCoverageFile :one
INSERT INTO coverage_files (coverage_report_id, file_path, line_rate, branch_rate, lines_valid, lines_covered, branches_valid, branches_covered)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListCoverageFilesByReport :many
SELECT * FROM coverage_files WHERE coverage_report_id = $1 ORDER BY file_path;

-- name: ListCoverageReportsBySnapshot :many
SELECT * FROM coverage_reports WHERE snapshot_id = $1 ORDER BY format;

-- name: GetLatestCoverageSnapshotIDByRef :one
SELECT s.id FROM snapshots s
JOIN coverage_reports cr ON cr.snapshot_id = s.id
WHERE s.ref_id = $1
  AND s.status != 'purged'
ORDER BY s.created_at DESC
LIMIT 1;

-- name: ListCoverageFilesBySnapshot :many
SELECT cf.* FROM coverage_files cf
JOIN coverage_reports cr ON cr.id = cf.coverage_report_id
WHERE cr.snapshot_id = $1
ORDER BY cf.file_path;

-- name: ListCoverageLinesBySnapshotFormat :many
SELECT cf.file_path, cl.line_number, cl.hits
FROM coverage_lines cl
JOIN coverage_files cf ON cf.id = cl.coverage_file_id
JOIN coverage_reports cr ON cr.id = cf.coverage_report_id
WHERE cr.snapshot_id = $1 AND cr.format = $2
ORDER BY cf.file_path, cl.line_number;

-- name: ListCoverageLinesBySnapshotPath :many
-- Suffix match narrows to candidate rows (tool prefixes like Go module paths);
-- the caller verifies each hit canonicalizes to the requested path.
SELECT cf.file_path, cl.line_number, cl.hits
FROM coverage_lines cl
JOIN coverage_files cf ON cf.id = cl.coverage_file_id
JOIN coverage_reports cr ON cr.id = cf.coverage_report_id
WHERE cr.snapshot_id = $1
  AND (cf.file_path = $2 OR cf.file_path LIKE '%/' || $2)
ORDER BY cf.file_path, cl.line_number;
