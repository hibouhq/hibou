package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hibouhq/lehibou/internal/store"
)

func (s *Server) resolveOrg(r *http.Request) (*store.Organization, error) {
	provider := chi.URLParam(r, "provider")
	slug := chi.URLParam(r, "slug")
	if provider == "" || slug == "" {
		return nil, nil
	}

	return s.queries.GetOrganizationByProviderAndSlug(r.Context(), provider, slug)
}