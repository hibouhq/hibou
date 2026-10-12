package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// applicabilityTimeout bounds one detection: listing a very large tree is
// many forge requests.
const applicabilityTimeout = 2 * time.Minute

type repoApplicabilityResponse struct {
	// Applicability is the latest detection, or null before the first one.
	Applicability *store.RepoApplicability `json:"applicability"`
}

// detectRepoApplicability lists the tracked paths at a ref and stores which
// catalog scanners apply (ADR-035 §3). Nothing in the repository runs. A
// forge that cannot list trees records an "unknown" result rather than
// nothing, so the UI can say why.
func (s *Server) detectRepoApplicability(ctx context.Context, repo *store.Repository, ref, commit string) (*store.RepoApplicability, error) {
	if s.scanCatalog == nil {
		return nil, errors.New("scanner catalog unavailable")
	}
	if ref == "" {
		ref = repo.DefaultBranch
	}
	var paths []string
	truncated := false
	provider := s.forges[repo.Provider]
	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if commit == "" {
		commit = ref
		if provider != nil && ok {
			if branch, err := provider.GetBranch(ctx, owner, name, ref); err == nil && branch != nil && branch.SHA != "" {
				commit = branch.SHA
			}
		}
	}
	if provider != nil && ok {
		if lister, ok := provider.(forge.TreeLister); ok {
			// Listing at the commit, not the branch name: the branch can
			// move between the two calls.
			listing, err := lister.ListTree(ctx, owner, name, commit)
			switch {
			case err == nil && listing != nil:
				paths, truncated = listing.Paths, listing.Truncated
			case errors.Is(err, forge.ErrFileNotFound):
			default:
				return nil, fmt.Errorf("list repository tree: %w", err)
			}
		}
	}
	overrides, err := s.scopeOverrides(ctx, repo)
	if err != nil {
		return nil, err
	}
	result := applicability.DetectWithOverrides(paths, truncated, s.scanCatalog, overrides)
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	stored, err := s.queries.UpsertRepoApplicability(ctx, store.RepoApplicability{
		RepoID:            repo.ID,
		RefName:           ref,
		CommitSHA:         commit,
		DetectionRevision: applicability.Revision,
		CatalogRevision:   s.scanCatalog.Revision,
		Status:            result.Status,
		Result:            encoded,
	})
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// refreshApplicabilityAsync re-detects after a push to the default branch,
// off the webhook path.
func (s *Server) refreshApplicabilityAsync(repo *store.Repository, ref string) {
	if s.scanCatalog == nil || repo == nil || ref != repo.DefaultBranch {
		return
	}
	base := s.lifecycleCtx
	if base == nil {
		base = context.Background()
	}
	go func() {
		ctx, cancel := context.WithTimeout(base, applicabilityTimeout)
		defer cancel()
		if _, err := s.detectRepoApplicability(ctx, repo, ref, ""); err != nil {
			s.log.Warn().Err(err).Str("repo", repo.Slug).Msg("applicability detection failed")
		}
	}()
}

// @Summary      Scanner applicability of a repository
// @Description  The latest detection of which catalog scanners apply (ADR-035 §3): languages, modules, excluded paths with reasons, and applicable scanners with their capabilities. Status "truncated" or "unknown" means the forge did not give a complete view; it is never proof that nothing applies.
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=server.repoApplicabilityResponse}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/applicability [get]
func (s *Server) handleGetRepoApplicability(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	latest, err := s.queries.GetLatestRepoApplicability(r.Context(), repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load applicability")
		return
	}
	api.JSON(w, http.StatusOK, repoApplicabilityResponse{Applicability: latest})
}

// @Summary      Re-detect scanner applicability
// @Description  Lists the default branch's tracked paths at its head commit and stores the detection. Reads the forge only; no repository code runs.
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=server.repoApplicabilityResponse}
// @Failure      502  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/applicability/refresh [post]
func (s *Server) handleRefreshRepoApplicability(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapUploads, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), applicabilityTimeout)
	defer cancel()
	detected, err := s.detectRepoApplicability(ctx, repo, repo.DefaultBranch, "")
	if err != nil {
		s.log.Warn().Err(err).Str("repo", repo.Slug).Msg("applicability detection failed")
		api.JSONError(w, http.StatusBadGateway, "could not list the repository through the forge")
		return
	}
	api.JSON(w, http.StatusOK, repoApplicabilityResponse{Applicability: detected})
}

// scopeOverrides loads the owners' refinements and the rule deciding which
// exclusions apply (ADR-035 §3): one that hides code in a language the org
// requires scanned needs an approved, unexpired exception for that path.
func (s *Server) scopeOverrides(ctx context.Context, repo *store.Repository) (applicability.Overrides, error) {
	stored, err := s.queries.ListRepoScopeOverrides(ctx, repo.ID)
	if err != nil {
		return applicability.Overrides{}, err
	}
	overrides := applicability.Overrides{}
	for _, override := range stored {
		switch override.Kind {
		case "exclude":
			overrides.Exclusions = append(overrides.Exclusions, applicability.OwnerExclusion{Path: override.Path, Reason: override.Reason})
		case "module_root":
			overrides.ModuleRoots = append(overrides.ModuleRoots, override.Path)
		}
	}
	if len(overrides.Exclusions) == 0 {
		return overrides, nil
	}
	requirements, err := s.queries.ListScannerRequirements(ctx, repo.OrgID)
	if err != nil {
		return applicability.Overrides{}, err
	}
	exceptions, err := s.queries.ListCoverageExceptionsByRepo(ctx, repo.ID)
	if err != nil {
		return applicability.Overrides{}, err
	}
	now := time.Now()
	overrides.Allow = func(path string, languages []string) (bool, string) {
		for _, language := range languages {
			for _, requirement := range requirements {
				if requirement.Language != language {
					continue
				}
				approved := false
				for _, exception := range exceptions {
					approved = approved || (exception.RequirementID == requirement.ID && exception.Scope == path &&
						exception.Status == "approved" && now.Before(exception.ExpiresAt))
				}
				if !approved {
					return false, "hides " + language + " code the organization requires scanned (" + requirement.Capability +
						"): request an exception for " + path
				}
			}
		}
		return true, ""
	}
	return overrides, nil
}
