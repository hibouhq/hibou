CREATE TABLE coverage_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    line_rate DOUBLE PRECISION,
    branch_rate DOUBLE PRECISION,
    lines_valid INT NOT NULL DEFAULT 0,
    lines_covered INT NOT NULL DEFAULT 0,
    branches_valid INT NOT NULL DEFAULT 0,
    branches_covered INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT coverage_reports_snapshot_key UNIQUE (snapshot_id)
);

CREATE TABLE coverage_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    coverage_report_id UUID NOT NULL REFERENCES coverage_reports(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_rate DOUBLE PRECISION,
    branch_rate DOUBLE PRECISION,
    lines_valid INT NOT NULL DEFAULT 0,
    lines_covered INT NOT NULL DEFAULT 0,
    branches_valid INT NOT NULL DEFAULT 0,
    branches_covered INT NOT NULL DEFAULT 0,
    CONSTRAINT coverage_files_report_path_key UNIQUE (coverage_report_id, file_path)
);
