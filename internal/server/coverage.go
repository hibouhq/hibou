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
	"github.com/hibouhq/hibou/internal/comparison"
	coverageparser "github.com/hibouhq/hibou/internal/coverage"
	"github.com/hibouhq/hibou/internal/store"
)

// Top-level numbers aggregate every report in the snapshot; per-tool views
// live under reports.
type coverageSummaryResponse struct {
	SnapshotID      string                 `json:"snapshot_id"`
	LineRate        *float64               `json:"line_rate"`
	BranchRate      *float64               `json:"branch_rate"`
	LinesValid      int                    `json:"lines_valid"`
	LinesCovered    int                    `json:"lines_covered"`
	BranchesValid   int                    `json:"branches_valid"`
	BranchesCovered int                    `json:"branches_covered"`
	Format          string                 `json:"format"`
	Files           []coverageFileResponse `json:"files"`
	Reports         []coverageFormatReport `json:"reports"`
	// NewCode is present only when ?since=<ref> asks for the new-code lens
	// (ADR-019): coverage of the lines changed since that baseline.
	NewCode *coverageNewCodeSummary `json:"new_code,omitempty"`
}

// coverageNewCodeSummary answers "of the code added since <baseline>, how much
// is tested?" — the SonarQube-style new-code view, computed from the forge's
// own comparison rather than a clone or blame store.
type coverageNewCodeSummary struct {
	Baseline  string   `json:"baseline"`
	BaseSHA   string   `json:"base_sha"`
	Lines     int      `json:"lines"`
	Covered   int      `json:"covered"`
	LineRate  *float64 `json:"line_rate"`
	Truncated bool     `json:"truncated"`
	FilePaths []string `json:"file_paths"`
}

type coverageFormatReport struct {
	// ReportID identifies the report row; two reports can share a format (e.g.
	// lcov from both TypeScript and Rust), so format is not an identity.
	ReportID string `json:"report_id"`
	// Scope is the top-level directory shared by every file in the report
	// ("ts", "rust"), letting the UI label same-format reports apart. Empty
	// when the report spans multiple roots.
	Scope           string                 `json:"scope,omitempty"`
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
	FilePath string `json:"file_path"`
	// CanonicalPath is repo-root-relative, with tool prefixes (Go module path,
	// Java package root) stripped, so the same file keys identically across
	// tools, snapshots, and the forge tree.
	CanonicalPath   string   `json:"canonical_path"`
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
		fileResponses := coverageFilesResponse(files, repo.Slug)
		responseReports = append(responseReports, coverageFormatReport{
			ReportID:        report.ID.String(),
			Scope:           coverageReportScope(fileResponses),
			LineRate:        report.LineRate,
			BranchRate:      report.BranchRate,
			LinesValid:      report.LinesValid,
			LinesCovered:    report.LinesCovered,
			BranchesValid:   report.BranchesValid,
			BranchesCovered: report.BranchesCovered,
			Format:          report.Format,
			Files:           fileResponses,
		})
	}

	orderedReports := orderCoverageReports(responseReports)
	aggregateFiles, totals := aggregateCoverageReports(orderedReports)
	format := "aggregate"
	if len(orderedReports) == 1 {
		format = orderedReports[0].Format
	}

	response := coverageSummaryResponse{
		SnapshotID:      snapshotID.String(),
		LineRate:        totals.LineRate,
		BranchRate:      totals.BranchRate,
		LinesValid:      totals.LinesValid,
		LinesCovered:    totals.LinesCovered,
		BranchesValid:   totals.BranchesValid,
		BranchesCovered: totals.BranchesCovered,
		Format:          format,
		Files:           aggregateFiles,
		Reports:         orderedReports,
	}
	response.NewCode = s.coverageNewCodeSince(r, repo, *snapshotID)

	api.JSON(w, http.StatusOK, response)
}

// coverageNewCodeSince computes the new-code coverage of the current snapshot
// relative to ?since=<ref> (a branch or release tag). Returns nil when no
// baseline was asked for, or when it cannot be resolved — the classic view then
// renders unchanged rather than showing a wrong number.
func (s *Server) coverageNewCodeSince(r *http.Request, repo *store.Repository, snapshotID uuid.UUID) *coverageNewCodeSummary {
	baseline := strings.TrimSpace(r.URL.Query().Get("since"))
	if baseline == "" {
		return nil
	}
	headSnapshot, err := s.queries.GetSnapshotByID(r.Context(), snapshotID)
	if err != nil || headSnapshot == nil || headSnapshot.CommitSHA == "" {
		return nil
	}
	baseRef, err := s.resolveRefForRepo(r, repo, baseline)
	if err != nil || baseRef == nil {
		return nil
	}
	baseSnapshot, err := s.queries.GetLatestNonPurgedSnapshotByRef(r.Context(), baseRef.ID)
	if err != nil || baseSnapshot == nil || baseSnapshot.CommitSHA == "" {
		return nil
	}
	patch := s.changedLinesForComparison(r.Context(), repo, s.forges[repo.Provider], baseSnapshot.CommitSHA, headSnapshot.CommitSHA)
	if patch == nil {
		return nil
	}

	headLines, err := s.loadSnapshotCoverageLines(r.Context(), snapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Msg("load per-line coverage for the new-code baseline")
		return nil
	}

	// Reuse the coverage-diff lens so the branch view and the compare view can
	// never disagree about what "new code coverage" means.
	diff := &comparison.CoverageDiff{Files: []comparison.CoverageFileDelta{}}
	changed := make(map[string][]int, len(patch.Files))
	for _, file := range patch.Files {
		if len(file.AddedLines) > 0 {
			changed[file.Path] = file.AddedLines
			diff.Files = append(diff.Files, comparison.CoverageFileDelta{FilePath: file.Path})
		}
	}
	cfg := s.loadCompareRepoConfig(r.Context(), repo)
	comparison.ApplyNewCodeLens(diff, changed, headLines, coverageExcludeGlobs(cfg), patch.Truncated)

	paths := make([]string, 0, len(diff.Files))
	for _, file := range diff.Files {
		if file.NewLines > 0 {
			paths = append(paths, file.FilePath)
		}
	}
	sort.Strings(paths)

	return &coverageNewCodeSummary{
		Baseline:  baseline,
		BaseSHA:   baseSnapshot.CommitSHA,
		Lines:     diff.NewLines,
		Covered:   diff.NewCovered,
		LineRate:  diff.NewLineRate,
		Truncated: diff.NewCodeTruncated,
		FilePaths: paths,
	}
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
		var fileID uuid.UUID
		if err := tx.QueryRowContext(ctx, `
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
			RETURNING id
		`,
			storedReport.ID,
			file.Path,
			coverageRateValue(coverageRatePtr(file.LineRate, file.LinesValid)),
			coverageRateValue(coverageRatePtr(file.BranchRate, file.BranchesValid)),
			file.LinesValid,
			file.LinesCovered,
			file.BranchesValid,
			file.BranchesCovered,
		).Scan(&fileID); err != nil {
			s.failCoverageUpload(snapshotID, report.Format, err)
			return
		}

		if err := s.persistCoverageLines(ctx, tx, fileID, file.Lines); err != nil {
			s.failCoverageUpload(snapshotID, report.Format, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		s.failCoverageUpload(snapshotID, report.Format, err)
		return
	}
}

// persistCoverageLines replaces the per-line hit rows for a coverage file.
// It is a no-op when line storage is disabled (HIBOU_COVERAGE_STORE_LINES=false)
// so large monorepos can opt out of the per-line row cost. Rows are always
// cleared first so a re-upload with fewer instrumented lines does not leave
// stale lines behind.
func (s *Server) persistCoverageLines(ctx context.Context, tx *sql.Tx, fileID uuid.UUID, lines []coverageparser.LineCoverage) error {
	if !s.cfg.CoverageStoreLines {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM coverage_lines WHERE coverage_file_id = $1`, fileID); err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	numbers := make([]int32, len(lines))
	hits := make([]int32, len(lines))
	branchesCovered := make([]int32, len(lines))
	branchesValid := make([]int32, len(lines))
	for i, line := range lines {
		numbers[i] = int32(line.Number)                  //nolint:gosec // G115: source line numbers are bounded by file size
		hits[i] = int32(line.Hits)                       //nolint:gosec // G115: hit counts are bounded by test executions
		branchesCovered[i] = int32(line.BranchesCovered) //nolint:gosec // G115: branch counts are bounded by line width
		branchesValid[i] = int32(line.BranchesValid)     //nolint:gosec // G115: branch counts are bounded by line width
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO coverage_lines (coverage_file_id, line_number, hits, branches_covered, branches_valid)
		SELECT $1, unnest($2::int[]), unnest($3::int[]), unnest($4::int[]), unnest($5::int[])
	`, fileID, pq.Array(numbers), pq.Array(hits), pq.Array(branchesCovered), pq.Array(branchesValid))
	return err
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

func coverageFilesResponse(files []store.CoverageFile, repoSlug string) []coverageFileResponse {
	response := make([]coverageFileResponse, len(files))
	for i, file := range files {
		response[i] = coverageFileResponse{
			FilePath:        file.FilePath,
			CanonicalPath:   canonicalCoveragePath(file.FilePath, repoSlug),
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
