package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

type TestReport struct {
	ID              uuid.UUID `json:"id"`
	SnapshotID      uuid.UUID `json:"snapshot_id"`
	Format          string    `json:"format"`
	Total           int       `json:"total"`
	Passed          int       `json:"passed"`
	Failed          int       `json:"failed"`
	Skipped         int       `json:"skipped"`
	Errors          int       `json:"errors"`
	DurationSeconds float64   `json:"duration_seconds"`
	CreatedAt       time.Time `json:"created_at"`
}

type TestCase struct {
	ID              uuid.UUID `json:"id"`
	TestReportID    uuid.UUID `json:"test_report_id"`
	Suite           string    `json:"suite"`
	Name            string    `json:"name"`
	Classname       string    `json:"classname"`
	Status          string    `json:"status"`
	DurationSeconds float64   `json:"duration_seconds"`
	Message         string    `json:"message"`
	FilePath        string    `json:"file_path"`
}

// GetTestReportBySnapshot returns a single report for a snapshot by aggregating
// every per-source report (e.g. Go + frontend junit) into summed totals, or nil
// when the snapshot has no reports. The returned ID is zero — callers list cases
// with ListTestCasesBySnapshot, not by report ID.
func (q *Queries) GetTestReportBySnapshot(ctx context.Context, snapshotID uuid.UUID) (*TestReport, error) {
	const query = `
		SELECT COALESCE(string_agg(DISTINCT format, ',' ORDER BY format), ''),
		       COALESCE(SUM(total), 0), COALESCE(SUM(passed), 0), COALESCE(SUM(failed), 0),
		       COALESCE(SUM(skipped), 0), COALESCE(SUM(errors), 0), COALESCE(SUM(duration_seconds), 0),
		       MAX(created_at), COUNT(*)
		FROM test_reports
		WHERE snapshot_id = $1
	`
	var (
		report    TestReport
		createdAt sql.NullTime
		count     int
	)
	if err := q.sqlDB.QueryRowContext(ctx, query, snapshotID).Scan(
		&report.Format, &report.Total, &report.Passed, &report.Failed, &report.Skipped,
		&report.Errors, &report.DurationSeconds, &createdAt, &count,
	); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	report.SnapshotID = snapshotID
	if createdAt.Valid {
		report.CreatedAt = createdAt.Time
	}
	return &report, nil
}

// GetLatestTestReportByRef aggregates the reports of the most recent snapshot of
// a ref that has any test report (regardless of status), mirroring coverage
// resolution.
func (q *Queries) GetLatestTestReportByRef(ctx context.Context, refID uuid.UUID) (*TestReport, error) {
	const query = `
		SELECT tr.snapshot_id
		FROM test_reports tr
		JOIN snapshots s ON s.id = tr.snapshot_id
		WHERE s.ref_id = $1
		ORDER BY s.created_at DESC
		LIMIT 1
	`
	var snapshotID uuid.UUID
	err := q.sqlDB.QueryRowContext(ctx, query, refID).Scan(&snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return q.GetTestReportBySnapshot(ctx, snapshotID)
}

// ListTestCasesBySnapshot returns every case across all of a snapshot's per-source
// reports (e.g. Go + frontend), failures and errors first. This is what the Tests
// tab renders so both languages' tests appear together.
func (q *Queries) ListTestCasesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]TestCase, error) {
	const query = `
		SELECT tc.id, tc.test_report_id, tc.suite, tc.name, tc.classname, tc.status, tc.duration_seconds, tc.message, tc.file_path
		FROM test_cases tc
		JOIN test_reports tr ON tr.id = tc.test_report_id
		WHERE tr.snapshot_id = $1
		ORDER BY
		  CASE tc.status WHEN 'error' THEN 0 WHEN 'failed' THEN 1 WHEN 'skipped' THEN 2 ELSE 3 END,
		  tc.suite, tc.name
	`
	rows, err := q.sqlDB.QueryContext(ctx, query, snapshotID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cases := []TestCase{}
	for rows.Next() {
		var c TestCase
		if err := rows.Scan(
			&c.ID, &c.TestReportID, &c.Suite, &c.Name, &c.Classname, &c.Status,
			&c.DurationSeconds, &c.Message, &c.FilePath,
		); err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, rows.Err()
}
