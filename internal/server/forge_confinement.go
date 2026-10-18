package server

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/metrics"
	"github.com/hibouhq/hibou/internal/store"
)

// ADR-052: check what each forge would let Hibou's identity write, warn when
// it reaches beyond hibou/* branches, and show the result to instance admins.

const (
	// forgeConfinementInterval spaces the checks: each one reads a few rules
	// per repository from the forge API, and rulesets rarely change.
	forgeConfinementInterval = 6 * time.Hour
	// forgeConfinementStartDelay keeps the first check out of startup.
	forgeConfinementStartDelay = time.Minute
	// forgeConfinementTimeout bounds one check across all forges.
	forgeConfinementTimeout = 10 * time.Minute
)

type confinementState struct {
	// run serialises checks on this replica.
	run sync.Mutex
	mu  sync.Mutex
	// report is the latest check, nil before the first one.
	report *forgeConfinementReport
}

type forgeConfinementReport struct {
	CheckedAt time.Time                `json:"checked_at"`
	Forges    []forgeConfinementResult `json:"forges"`
	startedAt time.Time
}

type forgeConfinementResult struct {
	// Forge is the configured forge id (HIBOU_FORGE_N_ID).
	Forge string `json:"forge"`
	// Provider is github, gitlab or forgejo.
	Provider string `json:"provider"`
	// UnconfinedRepositories counts the repositories with an error finding.
	UnconfinedRepositories int                        `json:"unconfined_repositories"`
	Findings               []forge.ConfinementFinding `json:"findings"`
	// Error is set when the check could not finish; Findings then holds what
	// it found before.
	Error string `json:"error,omitempty"`
}

func (s *Server) runForgeConfinementLoop(ctx context.Context) {
	timer := time.NewTimer(forgeConfinementStartDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		ran, err := store.WithLeaderLock(ctx, s.db, store.LockForgeConfinement, func(ctx context.Context) error {
			s.logForgeConfinement(s.checkForgeConfinement(ctx, time.Now()))
			return nil
		})
		switch {
		case err != nil && ctx.Err() == nil:
			s.log.Warn().Err(err).Msg("forge confinement check failed")
		case err == nil && !ran:
			s.log.Debug().Msg("another replica is checking forge confinement")
		}
		timer.Reset(forgeConfinementInterval)
	}
}

// checkForgeConfinement runs every forge's check, stores the report and
// updates the gauge. A check that started after notBefore, finished while
// this one waited for the lock, is returned instead of running another.
func (s *Server) checkForgeConfinement(ctx context.Context, notBefore time.Time) *forgeConfinementReport {
	s.confinement.run.Lock()
	defer s.confinement.run.Unlock()
	if latest := s.latestForgeConfinement(); latest != nil && !latest.startedAt.Before(notBefore) {
		return latest
	}
	started := time.Now()

	ctx, cancel := context.WithTimeout(ctx, forgeConfinementTimeout)
	defer cancel()

	ids := make([]string, 0, len(s.forges))
	for id := range s.forges {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	report := &forgeConfinementReport{Forges: make([]forgeConfinementResult, 0, len(ids)), startedAt: started}
	for _, id := range ids {
		provider := s.forges[id]
		checker, ok := provider.(forge.ConfinementChecker)
		if !ok {
			continue
		}
		findings, err := checker.CheckConfinement(ctx)
		result := forgeConfinementResult{Forge: id, Provider: provider.ID(), Findings: findings}
		if result.Findings == nil {
			result.Findings = []forge.ConfinementFinding{}
		}
		if err != nil {
			result.Error = err.Error()
		}
		unconfined := map[string]bool{}
		for _, finding := range findings {
			if finding.Severity == forge.ConfinementError {
				unconfined[finding.Repository] = true
			}
		}
		result.UnconfinedRepositories = len(unconfined)
		metrics.ForgeUnconfinedRepositories.WithLabelValues(id).Set(float64(len(unconfined)))
		report.Forges = append(report.Forges, result)
	}
	report.CheckedAt = time.Now().UTC()

	s.confinement.mu.Lock()
	s.confinement.report = report
	s.confinement.mu.Unlock()
	return report
}

// logForgeConfinement logs what an operator must fix, once per check.
func (s *Server) logForgeConfinement(report *forgeConfinementReport) {
	for _, result := range report.Forges {
		if result.Error != "" {
			s.log.Warn().Str("forge", result.Forge).Str("error", result.Error).Msg("forge confinement check incomplete")
		}
		for _, finding := range result.Findings {
			event := s.log.Debug()
			switch finding.Severity {
			case forge.ConfinementError:
				event = s.log.Error()
			case forge.ConfinementWarning:
				event = s.log.Warn()
			}
			event.Str("forge", result.Forge).
				Str("repository", finding.Repository).
				Str("code", finding.Code).
				Str("ruleset", finding.Ruleset).
				Msg("forge confinement: " + finding.Message)
		}
		if result.UnconfinedRepositories > 0 {
			s.log.Error().Str("forge", result.Forge).Int("repositories", result.UnconfinedRepositories).
				Msg("Hibou's forge identity can write outside hibou/* branches; see docs/DEPLOYMENT.md, \"confine the App\"")
		}
	}
}

func (s *Server) latestForgeConfinement() *forgeConfinementReport {
	s.confinement.mu.Lock()
	defer s.confinement.mu.Unlock()
	return s.confinement.report
}

// @Summary      Forge confinement
// @Description  For each forge, whether Hibou's identity (GitHub App, Forgejo token) could write outside hibou/* branches, per repository (ADR-052). Returns this replica's latest check, running one when there is none or when refresh=true. Instance admins only.
// @Tags         instance
// @Produce      json
// @Param        refresh  query     bool  false  "Run a new check first"
// @Success      200      {object}  api.Response{data=forgeConfinementReport}
// @Failure      401      {object}  api.Response
// @Failure      403      {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/forges/confinement [get]
func (s *Server) handleInstanceForgeConfinement(w http.ResponseWriter, r *http.Request) {
	if !s.requireInstanceAdmin(w, r) {
		return
	}
	report := s.latestForgeConfinement()
	if report == nil || r.URL.Query().Get("refresh") == "true" {
		report = s.checkForgeConfinement(r.Context(), time.Now())
	}
	api.JSON(w, http.StatusOK, report)
}
