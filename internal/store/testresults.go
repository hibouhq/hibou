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

const testReportColumns = "id, snapshot_id, format, total, passed, failed, skipped, errors, duration_seconds, created_at"

func scanTestReport(scanner interface{ Scan(...interface{}) error }) (*TestReport, error) {
	var report TestReport
	if err := scanner.Scan(
		&report.ID, &report.SnapshotID, &report.Format, &report.Total, &report.Passed,
		&report.Failed, &report.Skipped, &report.Errors, &report.DurationSeconds, &report.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &report, nil
}

// GetTestReportBySnapshot returns the test report for a specific snapshot, or nil.
func (q *Queries) GetTestReportBySnapshot(ctx context.Context, snapshotID uuid.UUID) (*TestReport, error) {
	row := q.sqlDB.QueryRowContext(ctx, "SELECT "+testReportColumns+" FROM test_reports WHERE snapshot_id = $1", snapshotID)
	report, err := scanTestReport(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return report, nil
}

// GetLatestTestReportByRef returns the most recent test report across all snapshots
// of a ref (regardless of snapshot status), mirroring coverage resolution.
func (q *Queries) GetLatestTestReportByRef(ctx context.Context, refID uuid.UUID) (*TestReport, error) {
	const query = `
		SELECT tr.id, tr.snapshot_id, tr.format, tr.total, tr.passed, tr.failed, tr.skipped, tr.errors, tr.duration_seconds, tr.created_at
		FROM test_reports tr
		JOIN snapshots s ON s.id = tr.snapshot_id
		WHERE s.ref_id = $1
		ORDER BY s.created_at DESC
		LIMIT 1
	`
	row := q.sqlDB.QueryRowContext(ctx, query, refID)
	report, err := scanTestReport(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return report, nil
}

// ListTestCasesByReport returns a report's cases, failures and errors first.
func (q *Queries) ListTestCasesByReport(ctx context.Context, reportID uuid.UUID) ([]TestCase, error) {
	const query = `
		SELECT id, test_report_id, suite, name, classname, status, duration_seconds, message, file_path
		FROM test_cases
		WHERE test_report_id = $1
		ORDER BY
		  CASE status WHEN 'error' THEN 0 WHEN 'failed' THEN 1 WHEN 'skipped' THEN 2 ELSE 3 END,
		  suite, name
	`
	rows, err := q.sqlDB.QueryContext(ctx, query, reportID)
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
