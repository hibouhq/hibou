package server

import (
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/repoinventory"
)

type syncReposResponse struct {
	Synced    bool                 `json:"synced"`
	Outcome   string               `json:"outcome"`
	Provider  string               `json:"provider"`
	Account   string               `json:"account"`
	RepoCount int                  `json:"repo_count"`
	Summary   repoInventorySummary `json:"summary"`
}

// @Summary      Sync forge repositories
// @Description  Reconcile the forge repository inventory for an organization
// @Tags         repositories
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Success      200       {object}  api.Response{data=server.syncReposResponse}
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Failure      503       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/sync [post]
func (s *Server) handleSyncRepos(w http.ResponseWriter, r *http.Request) {
	_, org, ok := s.loadAdminOrgForEnrollment(w, r)
	if !ok {
		return
	}
	if s.inventorySvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "repository inventory service unavailable")
		return
	}
	outcome, err := s.inventorySvc.Sync(r.Context(), org.Provider, org.Slug)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to sync repositories")
		return
	}
	repos, summary, err := s.listRepositoryInventory(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list synced repositories")
		return
	}
	api.JSON(w, http.StatusOK, syncReposResponse{
		Synced:    outcome == repoinventory.SyncOutcomeSynced,
		Outcome:   string(outcome),
		Provider:  org.Provider,
		Account:   org.Slug,
		RepoCount: len(repos),
		Summary:   summary,
	})
}
