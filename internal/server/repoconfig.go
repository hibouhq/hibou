package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
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

	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository coordinates")
		return
	}

	cfg, err := s.repoConfigLoader.Load(r.Context(), repo.Provider, owner, name, repo.DefaultBranch)
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

func (s *Server) handleOnboardRepo(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if s.onboardingSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "repo config onboarding unavailable")
		return
	}

	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository coordinates")
		return
	}

	pr, err := s.onboardingSvc.CreateOnboardingPR(r.Context(), repo.Provider, owner, name, repo.DefaultBranch)
	if err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("create onboarding pull request")
		api.JSONError(w, http.StatusBadGateway, "failed to create onboarding pull request")
		return
	}

	contextBody, _ := json.Marshal(map[string]any{"pr_number": pr.Number, "pr_url": pr.HTMLURL, "title": pr.Title})
	ipAddress, userAgent := audit.RequestContext(r)
	_, _ = s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID:      uuid.NullUUID{UUID: user.ID, Valid: true},
		ActorType:    audit.ActorUser,
		ActorDisplay: actorDisplay(user),
		Action:       audit.ActionOnboardingPR,
		ResourceType: "repository",
		ResourceID:   repo.ID.String(),
		OrgID:        uuid.NullUUID{UUID: org.ID, Valid: true},
		Context:      contextBody,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
	})

	api.JSON(w, http.StatusCreated, pr)
}

func (s *Server) handleGetConfigSchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/schema+json; charset=utf-8")
	_, _ = w.Write(repoconfig.SchemaBytes())
}

func (s *Server) loadAuthorizedRepoWithUser(w http.ResponseWriter, r *http.Request, requireAdmin bool) (*store.Organization, *store.Repository, *store.User, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil, nil, false
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, nil, nil, false
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, nil, nil, false
	}

	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, nil, nil, false
	}
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

	return org, repo, user, true
}

func (s *Server) resolveRepoWeaknessGate(ctx context.Context, providerID, defaultBranch, candidatesA, candidatesB, candidatesC string, targetSnapshotID uuid.UUID) *delta.WeaknessGate {
	if s.repoConfigLoader == nil {
		return nil
	}
	owner, name, ok := repoCoordinates(candidatesA, candidatesB, candidatesC)
	if !ok {
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

	cfg, err := s.repoConfigLoader.Load(ctx, providerID, owner, name, defaultBranch)
	if err != nil {
		s.log.Warn().Err(err).Str("provider", providerID).Str("owner", owner).Str("repo", name).Msg("failed to load repo config, falling back to DB gates")
		return nil
	}

	return matchedWeaknessGate(cfg, targetRef.Name)
}

func matchedWeaknessGate(cfg *repoconfig.RepoConfig, targetBranch string) *delta.WeaknessGate {
	if cfg == nil {
		return nil
	}
	gate := cfg.MatchGate(targetBranch)
	if gate == nil || gate.Weaknesses == nil {
		return nil
	}
	return &delta.WeaknessGate{
		Enabled:     gate.Weaknesses.Enabled,
		MaxCritical: gate.Weaknesses.MaxCritical,
		MaxHigh:     gate.Weaknesses.MaxHigh,
		MaxMedium:   gate.Weaknesses.MaxMedium,
	}
}

type repoConfigGateLoader struct {
	loader *repoconfig.Loader
}

func (l repoConfigGateLoader) LoadWeaknessGate(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.WeaknessGate, error) {
	if l.loader == nil {
		return nil, nil
	}
	cfg, err := l.loader.Load(ctx, providerID, owner, repo, defaultBranch)
	if err != nil {
		return nil, err
	}
	return matchedWeaknessGate(cfg, targetBranch), nil
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
