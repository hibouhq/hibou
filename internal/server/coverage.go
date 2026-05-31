package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	coverageparser "github.com/hibouhq/lehibou/internal/coverage"
	"github.com/hibouhq/lehibou/internal/store"
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

	report, err := s.queries.GetLatestCoverageByRef(r.Context(), ref.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load coverage report")
		return
	}
	if report == nil {
		api.JSON(w, http.StatusOK, nil)
		return
	}

	files, err := s.queries.ListCoverageFilesBySnapshot(r.Context(), report.SnapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load coverage files")
		return
	}

	response := coverageSummaryResponse{
		LineRate:        report.LineRate,
		BranchRate:      report.BranchRate,
		LinesValid:      report.LinesValid,
		LinesCovered:    report.LinesCovered,
		BranchesValid:   report.BranchesValid,
		BranchesCovered: report.BranchesCovered,
		Format:          report.Format,
		Files:           make([]coverageFileResponse, len(files)),
	}
	for i, file := range files {
		response.Files[i] = coverageFileResponse{
			FilePath:        file.FilePath,
			LineRate:        file.LineRate,
			BranchRate:      file.BranchRate,
			LinesValid:      file.LinesValid,
			LinesCovered:    file.LinesCovered,
			BranchesValid:   file.BranchesValid,
			BranchesCovered: file.BranchesCovered,
		}
	}

	api.JSON(w, http.StatusOK, response)
}

func (s *Server) processCoverageUpload(snapshotID uuid.UUID, content []byte, format string) {
	ctx := context.Background()

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
	storedReport, err := queries.CreateCoverageReport(
		ctx,
		snapshotID,
		report.Format,
		coverageRatePtr(report.LineRate, report.LinesValid),
		coverageRatePtr(report.BranchRate, report.BranchesValid),
		report.LinesValid,
		report.LinesCovered,
		report.BranchesValid,
		report.BranchesCovered,
	)
	if err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}

	for _, file := range report.Files {
		if _, err := queries.CreateCoverageFile(
			ctx,
			storedReport.ID,
			file.Path,
			coverageRatePtr(file.LineRate, file.LinesValid),
			coverageRatePtr(file.BranchRate, file.BranchesValid),
			file.LinesValid,
			file.LinesCovered,
			file.BranchesValid,
			file.BranchesCovered,
		); err != nil {
			s.failCoverageUpload(snapshotID, report.Format, err)
			return
		}
	}

	if _, err := queries.UpdateSnapshotStatus(ctx, snapshotID, store.SnapshotStatusComplete); err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
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
