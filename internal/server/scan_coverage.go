package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/scancoverage"
	"github.com/hibouhq/hibou/internal/scanplan"
	"github.com/hibouhq/hibou/internal/scanpolicy"
	"github.com/hibouhq/hibou/internal/store"
)

// coverageRefreshTimeout bounds one repository's recomputation.
const coverageRefreshTimeout = 30 * time.Second

// computeScanCoverage states the coverage of one repository (ADR-035 §6)
// from the runs given: the default branch's recent runs for the inventory,
// one PR head's runs for the check.
func (s *Server) computeScanCoverage(ctx context.Context, repo *store.Repository, runs []store.RefProducerRun) ([]scancoverage.Cell, error) {
	if s.scanCatalog == nil {
		return nil, nil
	}
	latest, err := s.queries.GetLatestRepoApplicability(ctx, repo.ID)
	if err != nil {
		return nil, err
	}
	var detected *applicability.Result
	status := applicability.StatusUnknown
	if latest != nil {
		var result applicability.Result
		if err := json.Unmarshal(latest.Result, &result); err != nil {
			return nil, err
		}
		detected, status = &result, result.Status
	}
	decisions, requirements, _, err := s.repoScannerDecisions(ctx, repo, detected)
	if err != nil {
		return nil, err
	}
	input := scancoverage.Input{
		Decisions:           decisions,
		Requirements:        map[uuid.UUID]scancoverage.Requirement{},
		ApplicabilityStatus: status,
		BundleCreatedAt:     s.offlineBundleCreatedAt(),
		Now:                 time.Now(),
	}
	for _, requirement := range requirements {
		input.Requirements[requirement.ID] = scancoverage.Requirement{ID: requirement.ID, Enforcement: requirement.Enforcement, FreshnessDays: requirement.FreshnessDays}
	}
	if stored, err := s.queries.GetLatestScanPlan(ctx, repo.ID); err == nil && stored != nil {
		var plan scanplan.Plan
		if json.Unmarshal(stored.Plan, &plan) == nil {
			input.Plan, input.PlanCreatedAt = &plan, stored.CreatedAt
		}
	}
	input.Runs = s.attributeRuns(ctx, repo, runs, decisions)
	return scancoverage.Compute(input), nil
}

// attributeRuns maps producer runs to catalog scanners. A run bound to a
// plan job is attributed through the plan (authenticated evidence); an
// unbound run through the catalog's producer names, preferring a scanner the
// policy runs — a name alone never counts as bound (ADR-035 §1).
func (s *Server) attributeRuns(ctx context.Context, repo *store.Repository, runs []store.RefProducerRun, decisions []scanpolicy.Decision) []scancoverage.Run {
	running := map[string]bool{}
	for _, decision := range decisions {
		if decision.Runs() {
			running[decision.ScannerID] = true
		}
	}
	plans := map[uuid.UUID]*scanplan.Plan{}
	out := make([]scancoverage.Run, 0, len(runs))
	for _, run := range runs {
		attributed := scancoverage.Run{Outcome: run.Outcome, Scope: run.Scope, At: run.CreatedAt, Commit: run.CommitSHA}
		if run.PlanID != nil && run.PlanJobID != nil {
			plan, ok := plans[*run.PlanID]
			if !ok {
				if stored, err := s.queries.GetScanPlan(ctx, repo.ID, *run.PlanID); err == nil && stored != nil {
					var decoded scanplan.Plan
					if json.Unmarshal(stored.Plan, &decoded) == nil {
						plan = &decoded
					}
				}
				plans[*run.PlanID] = plan
			}
			if plan != nil {
				for _, job := range plan.Jobs {
					if job.ID == *run.PlanJobID {
						attributed.ScannerID, attributed.Bound = job.ScannerID, true
					}
				}
			}
		}
		if attributed.ScannerID == "" {
			for _, scanner := range s.scanCatalog.ScannerForProducer(run.Producer) {
				if attributed.ScannerID == "" || (running[scanner.ID] && !running[attributed.ScannerID]) {
					attributed.ScannerID = scanner.ID
				}
			}
		}
		if attributed.ScannerID != "" {
			out = append(out, attributed)
		}
	}
	return out
}

// refreshRepoScanCoverage recomputes and persists a repository's cells from
// its default branch.
func (s *Server) refreshRepoScanCoverage(ctx context.Context, repo *store.Repository) ([]scancoverage.Cell, error) {
	ref, err := s.queries.GetRefByRepoAndName(ctx, repo.ID, repo.DefaultBranch, store.RefTypeBranch)
	if err != nil {
		return nil, err
	}
	runs := []store.RefProducerRun{}
	if ref != nil {
		if runs, err = s.queries.ListProducerRunsForRef(ctx, ref.ID); err != nil {
			return nil, err
		}
	}
	cells, err := s.computeScanCoverage(ctx, repo, runs)
	if err != nil {
		return nil, err
	}
	rows := make([]store.ScanCoverageCell, len(cells))
	for i, cell := range cells {
		rows[i] = store.ScanCoverageCell{
			ScannerID: cell.ScannerID, State: cell.State, Reason: cell.Reason, Configured: cell.Configured,
			Required: cell.Required, Enforcement: cell.Enforcement, LastRunAt: cell.LastRunAt, LastCommit: cell.LastCommit,
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.queries.WithTx(tx).ReplaceRepoScanCoverage(ctx, repo.ID, rows); err != nil {
		return nil, err
	}
	return cells, tx.Commit()
}

// refreshScanCoverageAsync recomputes off the request path; best effort.
func (s *Server) refreshScanCoverageAsync(repo *store.Repository) {
	if s.scanCatalog == nil || repo == nil {
		return
	}
	base := s.lifecycleCtx
	if base == nil {
		base = context.Background()
	}
	go func() {
		ctx, cancel := context.WithTimeout(base, coverageRefreshTimeout)
		defer cancel()
		if _, err := s.refreshRepoScanCoverage(ctx, repo); err != nil {
			s.log.Warn().Err(err).Str("repo", repo.Slug).Msg("scan coverage refresh failed")
		}
	}()
}

// prCoverageCheck is the gate's coverage evaluation for a PR head: the
// required scanners must have reported on this very snapshot.
func (s *Server) prCoverageCheck(ctx context.Context, repoID, headSnapshotID uuid.UUID) ([]string, []string, error) {
	repo, err := s.queries.GetRepositoryByID(ctx, repoID)
	if err != nil || repo == nil {
		return nil, nil, err
	}
	snapshot, err := s.queries.GetSnapshotByID(ctx, headSnapshotID)
	if err != nil || snapshot == nil {
		return nil, nil, err
	}
	runs, err := s.queries.ListProducerRunsBySnapshot(ctx, headSnapshotID)
	if err != nil {
		return nil, nil, err
	}
	withCommit := make([]store.RefProducerRun, len(runs))
	for i, run := range runs {
		withCommit[i] = store.RefProducerRun{ProducerRun: run, CommitSHA: snapshot.CommitSHA}
	}
	cells, err := s.computeScanCoverage(ctx, repo, withCommit)
	if err != nil {
		return nil, nil, err
	}
	var blocking, advisory []string
	for _, cell := range cells {
		if !cell.Required {
			continue
		}
		line := fmt.Sprintf("%s — %s", cell.ScannerID, cell.Reason)
		switch {
		case cell.State == scancoverage.StatePending:
			advisory = append(advisory, line+" (still pending)")
		case cell.Gap() && cell.Enforcement == "blocking":
			blocking = append(blocking, line)
		case cell.Gap():
			advisory = append(advisory, line)
		}
	}
	return blocking, advisory, nil
}

// @Summary      Scan coverage of a repository
// @Description  Per scanner: what the policy asks (configured) and what actually ran (state: covered, pending, missing, missing_setup, failed, partial, stale, unverified, unsupported, exempt, disabled, not_applicable, unknown), from the default branch's recent runs (ADR-035 §6). Recomputed on request.
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=[]scancoverage.Cell}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scan-coverage [get]
func (s *Server) handleGetRepoScanCoverage(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	cells, err := s.refreshRepoScanCoverage(r.Context(), repo)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to compute scan coverage")
		return
	}
	if cells == nil {
		cells = []scancoverage.Cell{}
	}
	api.JSON(w, http.StatusOK, cells)
}

type orgScanCoverageResponse struct {
	Cells   []store.ScanCoverageCell    `json:"cells"`
	Summary []store.ScanCoverageSummary `json:"summary"`
	Page    int                         `json:"page"`
	PerPage int                         `json:"per_page"`
}

// @Summary      Org scanner coverage matrix
// @Description  One row per repository × scanner from the persisted projection, required gaps first (ADR-035 §6). Filters: state, scanner, required=true. format=csv exports the filtered rows. The summary counts every state, not-applicable cells included, so the denominator is disclosed.
// @Tags         scanners
// @Produce      json
// @Param        provider  path   string  true   "Forge provider"
// @Param        slug      path   string  true   "Organization slug"
// @Param        state     query  string  false  "Cell state"
// @Param        scanner   query  string  false  "Scanner id"
// @Param        required  query  bool    false  "Required cells only"
// @Param        page      query  int     false  "Page (from 1)"
// @Param        per_page  query  int     false  "Rows per page (max 200)"
// @Param        format    query  string  false  "csv"
// @Success      200  {object}  api.Response{data=server.orgScanCoverageResponse}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/scan-coverage [get]
func (s *Server) handleGetOrgScanCoverage(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	perPage, _ := strconv.Atoi(query.Get("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	filter := store.OrgScanCoverageFilter{
		State: strings.TrimSpace(query.Get("state")), ScannerID: strings.TrimSpace(query.Get("scanner")),
		RequiredOnly: query.Get("required") == "true", Limit: perPage, Offset: (page - 1) * perPage,
	}
	csvExport := query.Get("format") == "csv"
	if csvExport {
		filter.Limit, filter.Offset = 10000, 0
	}
	cells, err := s.queries.ListOrgScanCoverage(r.Context(), org.ID, filter)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load scan coverage")
		return
	}
	if csvExport {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="scan-coverage.csv"`)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"repository", "scanner", "state", "configured", "required", "enforcement", "last_run_at", "last_commit", "reason"})
		for _, cell := range cells {
			lastRun := ""
			if cell.LastRunAt != nil {
				lastRun = cell.LastRunAt.UTC().Format(time.RFC3339)
			}
			_ = writer.Write([]string{csvSafe(cell.RepoSlug), cell.ScannerID, cell.State, cell.Configured, strconv.FormatBool(cell.Required), cell.Enforcement, lastRun, cell.LastCommit, csvSafe(cell.Reason)})
		}
		writer.Flush()
		return
	}
	summary, err := s.queries.SummarizeOrgScanCoverage(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to summarize scan coverage")
		return
	}
	api.JSON(w, http.StatusOK, orgScanCoverageResponse{Cells: cells, Summary: summary, Page: page, PerPage: perPage})
}

// csvSafe defuses spreadsheet formula injection in free text.
func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@\t\r", rune(value[0])) {
		return "'" + value
	}
	return value
}

// @Summary      Recompute the org scanner coverage matrix
// @Description  Org admins. Recomputes every repository's cells in the background, one at a time.
// @Tags         scanners
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      202
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/scan-coverage/refresh [post]
func (s *Server) handleRefreshOrgScanCoverage(w http.ResponseWriter, r *http.Request) {
	org, _, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	s.refreshOrgScanCoverageAsync(org.ID)
	w.WriteHeader(http.StatusAccepted)
}

// refreshOrgScanCoverageAsync recomputes every repository of an org,
// sequentially, after a change that affects them all (a requirement).
func (s *Server) refreshOrgScanCoverageAsync(orgID uuid.UUID) {
	if s.scanCatalog == nil {
		return
	}
	base := s.lifecycleCtx
	if base == nil {
		base = context.Background()
	}
	go func() {
		const pageSize = 200
		for offset := 0; ; offset += pageSize {
			repos, _, err := s.queries.ListRepositoriesByOrg(base, orgID, pageSize, offset)
			if err != nil {
				s.log.Warn().Err(err).Msg("org scan coverage refresh: list repositories")
				return
			}
			for i := range repos {
				ctx, cancel := context.WithTimeout(base, coverageRefreshTimeout)
				if _, err := s.refreshRepoScanCoverage(ctx, &repos[i]); err != nil {
					s.log.Warn().Err(err).Str("repo", repos[i].Slug).Msg("scan coverage refresh failed")
				}
				cancel()
			}
			if len(repos) < pageSize {
				return
			}
		}
	}()
}
