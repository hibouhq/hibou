package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/hibouhq/hibou/internal/cooldown"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

func (s *Server) handleGetRepoConfig(w http.ResponseWriter, r *http.Request) {
	org, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if s.repoConfigLoader == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "repo config loader unavailable")
		return
	}

	cfg, resolved, err := s.loadBoundRepoConfig(r.Context(), repo)
	if !resolved {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository coordinates")
		return
	}
	if err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("load repo config")
		api.JSONError(w, http.StatusBadGateway, "failed to load repository config")
		return
	}
	if cfg == nil {
		cfg, err = s.dbBackedRepoConfig(r.Context(), repo.ID, org.ID)
		if err != nil {
			s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("load DB-backed repo config")
			api.JSONError(w, http.StatusInternalServerError, "failed to load repository config")
			return
		}
	}

	api.JSON(w, http.StatusOK, cfg)
}

// handleGetOnboardingStatus reports the most recent onboarding PR opened for
// the repository, replayed from the audit log so the state survives reloads.
// The PR may since have been closed or merged; callers treat it as a hint.
func (s *Server) handleGetOnboardingStatus(w http.ResponseWriter, r *http.Request) {
	org, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}

	entry, err := s.queries.GetLatestRepoAuditLogByAction(r.Context(), org.ID, repo.ID, audit.ActionOnboardingPR)
	if err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("load onboarding audit log")
		api.JSONError(w, http.StatusInternalServerError, "failed to load onboarding status")
		return
	}

	var pr *forge.PullRequest
	if entry != nil {
		var recorded struct {
			Number int    `json:"pr_number"`
			URL    string `json:"pr_url"`
			Title  string `json:"title"`
		}
		if err := json.Unmarshal(entry.Context, &recorded); err == nil && recorded.URL != "" {
			pr = &forge.PullRequest{Number: recorded.Number, Title: recorded.Title, HTMLURL: recorded.URL}
		}
	}

	api.JSON(w, http.StatusOK, map[string]*forge.PullRequest{"pull_request": pr})
}

func (s *Server) handleOnboardRepo(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if s.onboardingSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "repo config onboarding unavailable")
		return
	}

	owner, name, ok := s.boundRepoCoordinates(r.Context(), repo)
	if !ok {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository coordinates")
		return
	}

	pr, err := s.onboardingSvc.CreateOnboardingPRForOrg(forgeOwnerContext(r.Context(), owner), org, repo.Provider, owner, name, repo.DefaultBranch)
	if errors.Is(err, repoconfig.ErrForeignRepository) {
		api.JSONError(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("create onboarding pull request")
		api.JSONError(w, http.StatusBadGateway, "failed to create onboarding pull request")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionOnboardingPR, map[string]any{
		"pr_number": pr.Number, "pr_url": pr.HTMLURL, "title": pr.Title,
	})

	api.JSON(w, http.StatusCreated, pr)
}

func (s *Server) handleGetConfigSchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/schema+json; charset=utf-8")
	_, _ = w.Write(repoconfig.SchemaBytes())
}

// loadAuthorizedRepoWithUser authorizes the request principal for a repo. The
// returned user is attribution, not authorization (ADR-022): it is nil for an
// org service principal, and callers must tolerate that.
func (s *Server) loadAuthorizedRepoWithUser(w http.ResponseWriter, r *http.Request, requireAdmin bool) (*store.Organization, *store.Repository, *store.User, bool) {
	org, role, ok := s.loadOrgMembership(r, w)
	if !ok {
		return nil, nil, nil, false
	}
	user := UserFromContext(r.Context())
	if requireAdmin && role != "admin" {
		api.JSONError(w, http.StatusForbidden, "admin access required")
		return nil, nil, nil, false
	}

	repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, chi.URLParam(r, "repoSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return nil, nil, nil, false
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return nil, nil, nil, false
	}
	// Repository visibility (§4.3) and the read-only roles (§4.4), shared with
	// loadAuthorizedRepo.
	if !s.authorizeRepoRequest(w, r, org.ID, role, repo) {
		return nil, nil, nil, false
	}

	return org, repo, user, true
}

// resolveRepoGateConfig loads the repo-config gate matching the target
// snapshot's ref. The repository is the one the target snapshot belongs to,
// and the forge is only reached with owner-bound coordinates
// (loadBoundRepoConfig): the coordinate arguments callers pass are ignored,
// since a name or slug is tenant-editable and once let one org read another
// org's config with its installation token.
func (s *Server) resolveRepoGateConfig(ctx context.Context, _, _, _, _, _ string, targetSnapshotID uuid.UUID) *delta.GateConfig {
	if s.repoConfigLoader == nil {
		return nil
	}

	targetSnapshot, err := s.queries.GetSnapshotByID(ctx, targetSnapshotID)
	if err != nil || targetSnapshot == nil {
		return nil
	}
	targetRef, err := s.queries.GetRefByID(ctx, targetSnapshot.RefID)
	if err != nil || targetRef == nil {
		return nil
	}
	repo, err := s.queries.GetRepositoryByID(ctx, targetRef.RepoID)
	if err != nil || repo == nil {
		return nil
	}

	cfg, resolved, err := s.loadBoundRepoConfig(ctx, repo)
	if !resolved {
		return nil
	}
	if err != nil {
		s.log.Warn().Err(err).Str("provider", repo.Provider).Str("repo_id", repo.ID.String()).Msg("failed to load repo config, falling back to DB gates")
		return nil
	}

	return matchedGateConfig(cfg, targetRef.Name)
}

// loadBoundRepoConfig loads a stored repository's config file from the forge.
// resolved is false when the repository has no coordinates owned by its org's
// forge account; nothing is fetched then. The forge context is bound to that
// owner (forge.WithInstallationOwner), so an installation token for any other
// account fails hard even if some code path below picks another owner.
func (s *Server) loadBoundRepoConfig(ctx context.Context, repo *store.Repository) (*repoconfig.RepoConfig, bool, error) {
	owner, name, ok := s.boundRepoCoordinates(ctx, repo)
	if !ok {
		return nil, false, nil
	}
	cfg, err := s.repoConfigLoader.Load(forgeOwnerContext(ctx, owner), repo.Provider, owner, name, repo.DefaultBranch)
	return cfg, true, err
}

// forgeOwnerContext binds ctx to the top-level account of an owner already
// checked against the org (boundRepoCoordinates).
func forgeOwnerContext(ctx context.Context, owner string) context.Context {
	account := strings.Trim(strings.TrimSpace(owner), "/")
	if i := strings.Index(account, "/"); i >= 0 {
		account = account[:i]
	}
	return forge.WithInstallationOwner(ctx, account)
}

func matchedGateConfig(cfg *repoconfig.RepoConfig, targetBranch string) *delta.GateConfig {
	if cfg == nil {
		return nil
	}
	out := &delta.GateConfig{}
	// The dependencies section applies whatever gate matches (ADR-048 §3):
	// the cooldown window and private namespaces are repository facts, not
	// per-branch thresholds.
	if cfg.Dependencies != nil {
		out.PrivateNamespaces = append(out.PrivateNamespaces, cfg.Dependencies.PrivateNamespaces...)
		if cfg.Dependencies.Cooldown != nil {
			gate := &delta.CooldownGate{Enforcement: cfg.Dependencies.Cooldown.Enforcement, InstallConfig: cfg.Dependencies.Cooldown.InstallConfig}
			if mode, duration, ok, err := cooldown.ParseWindow(cfg.Dependencies.Cooldown.Window); err == nil && ok {
				gate.WindowMode, gate.WindowDuration = mode, duration
			}
			out.Cooldown = gate
		}
		if g := cfg.Dependencies.GateNotShipped; g != nil {
			out.NotShipped = &delta.NotShippedGate{KEV: g.KEVValue(), EPSSMin: g.EPSSMin, MinSeverity: strings.ToLower(strings.TrimSpace(g.MinSeverity)), FixableOnly: g.FixableOnly}
		}
	}
	gate := cfg.MatchGate(targetBranch)
	if gate == nil {
		if out.Configured() || len(out.PrivateNamespaces) > 0 {
			return out
		}
		return nil
	}
	if gate.Code != nil {
		out.Code = &delta.CodeGate{
			Enabled:     gate.Code.Enabled,
			MaxCritical: gate.Code.MaxCritical,
			MaxHigh:     gate.Code.MaxHigh,
			MaxMedium:   gate.Code.MaxMedium,
		}
	}
	if gate.CWE != nil {
		// Parse validated the selectors, so an error cannot happen for a
		// loaded file; if it ever does, dropping the section would fail open,
		// so the gate carries the error and fails the evaluation instead.
		rules, err := gate.CWE.Selectors()
		cweGate := &delta.CWEGate{Types: gate.CWE.Types, MinSeverity: gate.CWE.MinSeverity, Invalid: err}
		for _, rule := range rules {
			cweGate.Rules = append(cweGate.Rules, delta.CWERule{Path: rule.Path, Selector: rule.Selector})
		}
		out.CWE = cweGate
	}
	if gate.Vulnerabilities != nil {
		out.Vulnerabilities = &delta.VulnerabilityGate{
			MaxCritical: gate.Vulnerabilities.MaxCritical,
			MaxHigh:     gate.Vulnerabilities.MaxHigh,
			MaxMedium:   gate.Vulnerabilities.MaxMedium,
			MaxUnknown:  gate.Vulnerabilities.MaxUnknown,
			MaxNewTotal: gate.Vulnerabilities.MaxNewTotal,
		}
	}
	if gate.Licenses != nil {
		out.Licenses = &delta.LicenseGate{
			DenyCategories: gate.Licenses.DenyCategories,
			Deny:           gate.Licenses.Deny,
			Allow:          gate.Licenses.Allow,
			DenyUnknown:    gate.Licenses.DenyUnknownValue(),
			ExemptPurls:    gate.Licenses.ExemptPurls,
			Evaluate:       gate.Licenses.EvaluateValue(),
		}
	}
	if gate.Secrets != nil {
		out.Secrets = &delta.SecretsGate{
			MaxNew: gate.Secrets.MaxNew,
		}
	}
	if !out.Configured() && len(out.PrivateNamespaces) == 0 {
		return nil
	}
	return out
}

type repoConfigGateLoader struct {
	loader *repoconfig.Loader
}

func (l repoConfigGateLoader) LoadGateConfig(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.GateConfig, error) {
	if l.loader == nil {
		return nil, nil
	}
	cfg, err := l.loader.Load(ctx, providerID, owner, repo, defaultBranch)
	if err != nil {
		return nil, err
	}
	return matchedGateConfig(cfg, targetBranch), nil
}

// LoadEnforcement returns the enforcement mode (advisory|blocking) of the gate
// matching targetBranch, defaulting to advisory when no repo config or match.
func (l repoConfigGateLoader) LoadEnforcement(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (string, error) {
	if l.loader == nil {
		return repoconfig.EnforcementAdvisory, nil
	}
	cfg, err := l.loader.Load(ctx, providerID, owner, repo, defaultBranch)
	if err != nil {
		return repoconfig.EnforcementAdvisory, err
	}
	if cfg == nil {
		return repoconfig.EnforcementAdvisory, nil
	}
	return cfg.MatchGate(targetBranch).EnforcementValue(), nil
}

func (s *Server) dbBackedRepoConfig(ctx context.Context, repoID, orgID uuid.UUID) (*repoconfig.RepoConfig, error) {
	if s == nil || s.queries == nil {
		return &repoconfig.RepoConfig{Version: repoconfig.CurrentVersion}, nil
	}
	gates, err := s.queries.ListQualityGatesByRepo(ctx, uuid.NullUUID{UUID: repoID, Valid: true})
	if err != nil {
		return nil, err
	}
	if len(gates) == 0 {
		gates, err = s.queries.ListOrgWideQualityGates(ctx, orgID)
		if err != nil {
			return nil, err
		}
	}
	for _, gate := range gates {
		if gate.Enabled && gate.MaxNewFindings.Valid {
			return &repoconfig.RepoConfig{Version: repoconfig.CurrentVersion}, nil
		}
	}
	return &repoconfig.RepoConfig{Version: repoconfig.CurrentVersion}, nil
}

// boundRepoCoordinates is repoCoordinates for a stored repository, refusing
// coordinates whose owner is not the forge account the repository's org is
// bound to. Every forge call made on a repository's behalf mints the owner's
// installation token, so a row naming another tenant's repository must not
// reach the forge (security audit §3.1) — enrolment refuses such rows, this
// covers rows that predate that check.
func (s *Server) boundRepoCoordinates(ctx context.Context, repo *store.Repository) (string, string, bool) {
	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		return "", "", false
	}
	bound, err := s.queries.ForgeOwnerBoundToOrg(ctx, repo.OrgID, owner)
	if err != nil || !bound {
		s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Str("owner", owner).
			Msg("repository owner is not the organization's forge account; skipping forge call")
		return "", "", false
	}
	return owner, name, true
}

func repoCoordinates(candidates ...string) (string, string, bool) {
	for _, candidate := range candidates {
		owner, name, ok := splitRepoCoordinate(candidate)
		if ok {
			return owner, name, true
		}
	}
	return "", "", false
}

func splitRepoCoordinate(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func actorDisplay(user *store.User) string {
	if user == nil {
		return ""
	}
	if strings.TrimSpace(user.DisplayName) != "" {
		return strings.TrimSpace(user.DisplayName)
	}
	return strings.TrimSpace(user.Email)
}
