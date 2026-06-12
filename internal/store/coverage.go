package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type CoverageReport struct {
	ID              uuid.UUID `json:"id"`
	SnapshotID      uuid.UUID `json:"snapshot_id"`
	Format          string    `json:"format"`
	LineRate        *float64  `json:"line_rate,omitempty"`
	BranchRate      *float64  `json:"branch_rate,omitempty"`
	LinesValid      int       `json:"lines_valid"`
	LinesCovered    int       `json:"lines_covered"`
	BranchesValid   int       `json:"branches_valid"`
	BranchesCovered int       `json:"branches_covered"`
	CreatedAt       time.Time `json:"created_at"`
}

type CoverageFile struct {
	ID               uuid.UUID `json:"id"`
	CoverageReportID uuid.UUID `json:"coverage_report_id"`
	FilePath         string    `json:"file_path"`
	LineRate         *float64  `json:"line_rate,omitempty"`
	BranchRate       *float64  `json:"branch_rate,omitempty"`
	LinesValid       int       `json:"lines_valid"`
	LinesCovered     int       `json:"lines_covered"`
	BranchesValid    int       `json:"branches_valid"`
	BranchesCovered  int       `json:"branches_covered"`
}

func (q *Queries) CreateCoverageReport(ctx context.Context, snapshotID uuid.UUID, format string, lineRate, branchRate *float64, linesValid, linesCovered, branchesValid, branchesCovered int) (*CoverageReport, error) {
	row, err := q.db.CreateCoverageReport(ctx, dbgen.CreateCoverageReportParams{
		SnapshotID:      snapshotID,
		Format:          format,
		LineRate:        nullFloat64FromPtr(lineRate),
		BranchRate:      nullFloat64FromPtr(branchRate),
		LinesValid:      int32(linesValid),      //nolint:gosec // G115: value bounded by file metrics
		LinesCovered:    int32(linesCovered),    //nolint:gosec // G115: value bounded by file metrics
		BranchesValid:   int32(branchesValid),   //nolint:gosec // G115: value bounded by file metrics
		BranchesCovered: int32(branchesCovered), //nolint:gosec // G115: value bounded by file metrics
	})
	if err != nil {
		return nil, err
	}

	return coverageReportFromRow(row), nil
}

func (q *Queries) GetCoverageReportBySnapshot(ctx context.Context, snapshotID uuid.UUID) (*CoverageReport, error) {
	row, err := q.db.GetCoverageReportBySnapshot(ctx, snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return coverageReportFromRow(row), nil
}

func (q *Queries) CreateCoverageFile(ctx context.Context, coverageReportID uuid.UUID, filePath string, lineRate, branchRate *float64, linesValid, linesCovered, branchesValid, branchesCovered int) (*CoverageFile, error) {
	row, err := q.db.CreateCoverageFile(ctx, dbgen.CreateCoverageFileParams{
		CoverageReportID: coverageReportID,
		FilePath:         filePath,
		LineRate:         nullFloat64FromPtr(lineRate),
		BranchRate:       nullFloat64FromPtr(branchRate),
		LinesValid:       int32(linesValid),      //nolint:gosec // G115: value bounded by file metrics
		LinesCovered:     int32(linesCovered),    //nolint:gosec // G115: value bounded by file metrics
		BranchesValid:    int32(branchesValid),   //nolint:gosec // G115: value bounded by file metrics
		BranchesCovered:  int32(branchesCovered), //nolint:gosec // G115: value bounded by file metrics
	})
	if err != nil {
		return nil, err
	}

	return coverageFileFromRow(row), nil
}

func (q *Queries) ListCoverageFilesByReport(ctx context.Context, coverageReportID uuid.UUID) ([]CoverageFile, error) {
	rows, err := q.db.ListCoverageFilesByReport(ctx, coverageReportID)
	if err != nil {
		return nil, err
	}

	files := make([]CoverageFile, len(rows))
	for i, row := range rows {
		files[i] = *coverageFileFromRow(row)
	}

	return files, nil
}

func (q *Queries) GetLatestCoverageByRef(ctx context.Context, refID uuid.UUID) (*CoverageReport, error) {
	row, err := q.db.GetLatestCoverageByRef(ctx, refID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return coverageReportFromRow(row), nil
}

func (q *Queries) ListCoverageFilesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]CoverageFile, error) {
	rows, err := q.db.ListCoverageFilesBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}

	files := make([]CoverageFile, len(rows))
	for i, row := range rows {
		files[i] = *coverageFileFromRow(row)
	}

	return files, nil
}

func coverageReportFromRow(row dbgen.CoverageReport) *CoverageReport {
	return &CoverageReport{
		ID:              row.ID,
		SnapshotID:      row.SnapshotID,
		Format:          row.Format,
		LineRate:        float64PtrFromNull(row.LineRate),
		BranchRate:      float64PtrFromNull(row.BranchRate),
		LinesValid:      int(row.LinesValid),
		LinesCovered:    int(row.LinesCovered),
		BranchesValid:   int(row.BranchesValid),
		BranchesCovered: int(row.BranchesCovered),
		CreatedAt:       row.CreatedAt,
	}
}

func coverageFileFromRow(row dbgen.CoverageFile) *CoverageFile {
	return &CoverageFile{
		ID:               row.ID,
		CoverageReportID: row.CoverageReportID,
		FilePath:         row.FilePath,
		LineRate:         float64PtrFromNull(row.LineRate),
		BranchRate:       float64PtrFromNull(row.BranchRate),
		LinesValid:       int(row.LinesValid),
		LinesCovered:     int(row.LinesCovered),
		BranchesValid:    int(row.BranchesValid),
		BranchesCovered:  int(row.BranchesCovered),
	}
}
