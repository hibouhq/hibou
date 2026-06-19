package server

import (
	"context"
	"database/sql"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/api"
	coverageparser "github.com/hibouhq/hibou/internal/coverage"
	"github.com/hibouhq/hibou/internal/store"
)

type coverageSummaryResponse struct {
	LineRate        *float64               `json:"line_rate"`
	BranchRate      *float64               `json:"branch_rate"`
	LinesValid      int                    `json:"lines_valid"`
	LinesCovered    int                    `json:"lines_covered"`
	BranchesValid   int                    `json:"branches_valid"`
	BranchesCovered int                    `json:"branches_covered"`
	Format          string                 `json:"format"`
	Files           []coverageFileResponse `json:"files"`
	Reports         []coverageFormatReport `json:"reports"`
}

type coverageFormatReport struct {
	LineRate        *float64               `json:"line_rate"`
	BranchRate      *float64               `json:"branch_rate"`
	LinesValid      int                    `json:"lines_valid"`
	LinesCovered    int                    `json:"lines_covered"`
	BranchesValid   int                    `json:"branches_valid"`
	BranchesCovered int                    `json:"branches_covered"`
	Format          string                 `json:"format"`
	Files           []coverageFileResponse `json:"files"`
}

type coverageFileResponse struct {
	FilePath        string   `json:"file_path"`
	LineRate        *float64 `json:"line_rate"`
	BranchRate      *float64 `json:"branch_rate"`
	LinesValid      int      `json:"lines_valid"`
	LinesCovered    int      `json:"lines_covered"`
	BranchesValid   int      `json:"branches_valid"`
	BranchesCovered int      `json:"branches_covered"`
}

func (s *Server) handleGetCoverage(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	refName := strings.TrimSpace(r.URL.Query().Get("ref"))
	if refName == "" {
		refName = repo.DefaultBranch
	}
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return
	}

	ref, err := s.resolveRefForRepo(r, repo, refName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository reference")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "ref not found")
		return
	}

	snapshotID, err := s.queries.GetLatestCoverageSnapshotIDByRef(r.Context(), ref.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load coverage report")
		return
	}
	if snapshotID == nil {
		api.JSON(w, http.StatusOK, nil)
		return
	}

	reports, err := s.queries.ListCoverageReportsBySnapshot(r.Context(), *snapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load coverage reports")
		return
	}
	if len(reports) == 0 {
		api.JSON(w, http.StatusOK, nil)
		return
	}

	responseReports := make([]coverageFormatReport, 0, len(reports))
	for _, report := range reports {
		files, fileErr := s.queries.ListCoverageFilesByReport(r.Context(), report.ID)
		if fileErr != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load coverage files")
			return
		}
		responseReports = append(responseReports, coverageFormatReport{
			LineRate:        report.LineRate,
			BranchRate:      report.BranchRate,
			LinesValid:      report.LinesValid,
			LinesCovered:    report.LinesCovered,
			BranchesValid:   report.BranchesValid,
			BranchesCovered: report.BranchesCovered,
			Format:          report.Format,
			Files:           coverageFilesResponse(files),
		})
	}

	orderedReports := orderCoverageReports(responseReports)
	primary := orderedReports[0]

	response := coverageSummaryResponse{
		LineRate:        primary.LineRate,
		BranchRate:      primary.BranchRate,
		LinesValid:      primary.LinesValid,
		LinesCovered:    primary.LinesCovered,
		BranchesValid:   primary.BranchesValid,
		BranchesCovered: primary.BranchesCovered,
		Format:          primary.Format,
		Files:           primary.Files,
		Reports:         orderedReports,
	}

	api.JSON(w, http.StatusOK, response)
}

func (s *Server) processCoverageUpload(ctx context.Context, snapshotID uuid.UUID, content []byte, format string) {
	report, err := coverageparser.Parse(content, format)
	if err != nil {
		s.failCoverageUpload(snapshotID, format, err)
		return
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := s.queries.WithTx(tx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO coverage_reports (
			snapshot_id,
			format,
			line_rate,
			branch_rate,
			lines_valid,
			lines_covered,
			branches_valid,
			branches_covered
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (snapshot_id, format) DO UPDATE
		SET
			line_rate = EXCLUDED.line_rate,
			branch_rate = EXCLUDED.branch_rate,
			lines_valid = EXCLUDED.lines_valid,
			lines_covered = EXCLUDED.lines_covered,
			branches_valid = EXCLUDED.branches_valid,
			branches_covered = EXCLUDED.branches_covered
	`,
		snapshotID,
		report.Format,
		coverageRateValue(coverageRatePtr(report.LineRate, report.LinesValid)),
		coverageRateValue(coverageRatePtr(report.BranchRate, report.BranchesValid)),
		report.LinesValid,
		report.LinesCovered,
		report.BranchesValid,
		report.BranchesCovered,
	); err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}
	storedReport, err := queries.GetCoverageReportBySnapshotFormat(ctx, snapshotID, report.Format)
	if err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}
	if storedReport == nil {
		s.failCoverageUpload(snapshotID, report.Format, sql.ErrNoRows)
		return
	}

	filePaths := make([]string, len(report.Files))
	for i, file := range report.Files {
		filePaths[i] = file.Path
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM coverage_files
		WHERE coverage_report_id = $1
		  AND NOT (file_path = ANY($2::text[]))
	`, storedReport.ID, pq.Array(filePaths)); err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}

	for _, file := range report.Files {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO coverage_files (
				coverage_report_id,
				file_path,
				line_rate,
				branch_rate,
				lines_valid,
				lines_covered,
				branches_valid,
				branches_covered
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (coverage_report_id, file_path) DO UPDATE
			SET
				line_rate = EXCLUDED.line_rate,
				branch_rate = EXCLUDED.branch_rate,
				lines_valid = EXCLUDED.lines_valid,
				lines_covered = EXCLUDED.lines_covered,
				branches_valid = EXCLUDED.branches_valid,
				branches_covered = EXCLUDED.branches_covered
		`,
			storedReport.ID,
			file.Path,
			coverageRateValue(coverageRatePtr(file.LineRate, file.LinesValid)),
			coverageRateValue(coverageRatePtr(file.BranchRate, file.BranchesValid)),
			file.LinesValid,
			file.LinesCovered,
			file.BranchesValid,
			file.BranchesCovered,
		); err != nil {
			s.failCoverageUpload(snapshotID, report.Format, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}
}

func (s *Server) failCoverageUpload(snapshotID uuid.UUID, format string, cause error) {
	s.log.Error().Err(cause).Str("snapshot_id", snapshotID.String()).Str("format", format).Msg("failed to process coverage upload")
	if _, err := s.queries.UpdateSnapshotStatus(context.Background(), snapshotID, store.SnapshotStatusFailed); err != nil {
		s.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("failed to mark coverage snapshot as failed")
	}
}

func coverageRatePtr(value float64, valid int) *float64 {
	if valid <= 0 {
		return nil
	}
	result := value
	return &result
}

func coverageRateValue(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func coverageFilesResponse(files []store.CoverageFile) []coverageFileResponse {
	response := make([]coverageFileResponse, len(files))
	for i, file := range files {
		response[i] = coverageFileResponse{
			FilePath:        file.FilePath,
			LineRate:        file.LineRate,
			BranchRate:      file.BranchRate,
			LinesValid:      file.LinesValid,
			LinesCovered:    file.LinesCovered,
			BranchesValid:   file.BranchesValid,
			BranchesCovered: file.BranchesCovered,
		}
	}

	return response
}

func orderCoverageReports(reports []coverageFormatReport) []coverageFormatReport {
	ordered := append([]coverageFormatReport(nil), reports...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].LinesValid != ordered[j].LinesValid {
			return ordered[i].LinesValid > ordered[j].LinesValid
		}
		return ordered[i].Format < ordered[j].Format
	})
	return ordered
}
