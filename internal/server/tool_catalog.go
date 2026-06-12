package server

import (
	"net/http"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
)

func (s *Server) handleGetToolCatalog(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if s.toolCatalogSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "tool catalog unavailable")
		return
	}

	orgName := strings.TrimSpace(org.DisplayName)
	if orgName == "" {
		orgName = org.Name
	}

	catalog, err := s.toolCatalogSvc.Catalog(r.Context(), org.ID, orgName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to build tool catalog")
		return
	}

	api.JSON(w, http.StatusOK, catalog)
}
