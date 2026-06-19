package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
	testparser "github.com/hibouhq/hibou/internal/testresults"
)

type testReportResponse struct {
	Format          string             `json:"format"`
	Total           int                `json:"total"`
	Passed          int                `json:"passed"`
	Failed          int                `json:"failed"`
	Skipped         int                `json:"skipped"`
	Errors          int                `json:"errors"`
	DurationSeconds float64            `json:"duration_seconds"`
	Cases           []testCaseResponse `json:"cases"`
}

type testCaseResponse struct {
	Suite           string  `json:"suite"`
	Name            string  `json:"name"`
	Classname       string  `json:"classname"`
	Status          string  `json:"status"`
	DurationSeconds float64 `json:"duration_seconds"`
	Message         string  `json:"message"`
	FilePath        string  `json:"file_path"`
}

// handleGetTests godoc
// @Summary      Get test results
// @Description  Returns the latest test report (JUnit) for a ref or snapshot.
// @Tags         analysis
// @Produce      json
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        ref query string false "Ref name (defaults to the default branch)"
// @Param        snapshot query string false "Snapshot ID (overrides ref)"
// @Success      200 {object} testReportResponse
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/tests [get]
func (s *Server) handleGetTests(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	report, ok := s.resolveTestReport(r, w, repo)
	if !ok {
		return
	}
	if report == nil {
		api.JSON(w, http.StatusOK, nil)
		return
	}

	cases, err := s.queries.ListTestCasesByReport(r.Context(), report.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load test cases")
		return
	}

	response := testReportResponse{
		Format:          report.Format,
		Total:           report.Total,
		Passed:          report.Passed,
		Failed:          report.Failed,
		Skipped:         report.Skipped,
		Errors:          report.Errors,
		DurationSeconds: report.DurationSeconds,
		Cases:           make([]testCaseResponse, len(cases)),
	}
	for i, c := range cases {
		response.Cases[i] = testCaseResponse{
			Suite:           c.Suite,
			Name:            c.Name,
			Classname:       c.Classname,
			Status:          c.Status,
			DurationSeconds: c.DurationSeconds,
			Message:         c.Message,
			FilePath:        c.FilePath,
		}
	}

	api.JSON(w, http.StatusOK, response)
}

func (s *Server) resolveTestReport(r *http.Request, w http.ResponseWriter, repo *store.Repository) (*store.TestReport, bool) {
	if snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot")); snapshotID != "" {
		snapshot, status, message := s.loadSnapshotForRepoByID(r, repo, snapshotID)
		if status != 0 {
			api.JSONError(w, status, message)
			return nil, false
		}
		report, err := s.queries.GetTestReportBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load test report")
			return nil, false
		}
		return report, true
	}

	refName := strings.TrimSpace(r.URL.Query().Get("ref"))
	if refName == "" {
		refName = repo.DefaultBranch
	}
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return nil, false
	}

	ref, err := s.resolveRefForRepo(r, repo, refName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository reference")
		return nil, false
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "ref not found")
		return nil, false
	}

	report, err := s.queries.GetLatestTestReportByRef(r.Context(), ref.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load test report")
		return nil, false
	}
	return report, true
}

func (s *Server) processTestUpload(ctx context.Context, snapshotID uuid.UUID, content []byte, format string) {
	report, err := testparser.Parse(content, format)
	if err != nil {
		s.failTestUpload(snapshotID, format, err)
		return
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.failTestUpload(snapshotID, report.Format, err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	const insertReport = `
		INSERT INTO test_reports (snapshot_id, format, total, passed, failed, skipped, errors, duration_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (snapshot_id) DO UPDATE SET
		  format = EXCLUDED.format, total = EXCLUDED.total, passed = EXCLUDED.passed,
		  failed = EXCLUDED.failed, skipped = EXCLUDED.skipped, errors = EXCLUDED.errors,
		  duration_seconds = EXCLUDED.duration_seconds
		RETURNING id
	`
	var reportID uuid.UUID
	if err := tx.QueryRowContext(ctx, insertReport, snapshotID, report.Format, report.Total, report.Passed, report.Failed, report.Skipped, report.Errors, report.DurationSeconds).Scan(&reportID); err != nil {
		s.failTestUpload(snapshotID, report.Format, err)
		return
	}

	// Replace any prior cases (idempotent re-upload).
	if _, err := tx.ExecContext(ctx, "DELETE FROM test_cases WHERE test_report_id = $1", reportID); err != nil {
		s.failTestUpload(snapshotID, report.Format, err)
		return
	}

	const insertCase = `
		INSERT INTO test_cases (test_report_id, suite, name, classname, status, duration_seconds, message, file_path)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	for _, c := range report.Cases {
		if _, err := tx.ExecContext(ctx, insertCase, reportID, c.Suite, c.Name, c.Classname, c.Status, c.DurationSeconds, truncateTestMessage(c.Message), c.FilePath); err != nil {
			s.failTestUpload(snapshotID, report.Format, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		s.failTestUpload(snapshotID, report.Format, err)
	}
}

func truncateTestMessage(value string) string {
	const limit = 4000
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func (s *Server) failTestUpload(snapshotID uuid.UUID, format string, cause error) {
	s.log.Error().Err(cause).Str("snapshot_id", snapshotID.String()).Str("format", format).Msg("failed to process test report upload")
	if _, err := s.queries.UpdateSnapshotStatus(context.Background(), snapshotID, store.SnapshotStatusFailed); err != nil {
		s.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("failed to mark test snapshot as failed")
	}
}
