CREATE TABLE test_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    total INT NOT NULL DEFAULT 0,
    passed INT NOT NULL DEFAULT 0,
    failed INT NOT NULL DEFAULT 0,
    skipped INT NOT NULL DEFAULT 0,
    errors INT NOT NULL DEFAULT 0,
    duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT test_reports_snapshot_key UNIQUE (snapshot_id)
);

CREATE TABLE test_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_report_id UUID NOT NULL REFERENCES test_reports(id) ON DELETE CASCADE,
    suite TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    classname TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    CONSTRAINT test_cases_status_check CHECK (status IN ('passed', 'failed', 'skipped', 'error'))
);

CREATE INDEX idx_test_cases_report ON test_cases (test_report_id);
CREATE INDEX idx_test_cases_report_status ON test_cases (test_report_id, status);
