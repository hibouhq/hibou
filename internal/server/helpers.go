package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

func (s *Server) resolveOrg(r *http.Request) (*store.Organization, error) {
	provider := chi.URLParam(r, "provider")
	slug := chi.URLParam(r, "slug")
	if provider == "" || slug == "" {
		return nil, nil
	}

	return s.queries.GetOrganizationByProviderAndSlug(r.Context(), provider, slug)
}

func parseUUIDParam(r *http.Request, name string) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, name))
}

func paginateItems[T any](items []T, pagination api.PaginationParams) []T {
	if pagination.Offset >= len(items) {
		return []T{}
	}

	end := pagination.Offset + pagination.PerPage
	if end > len(items) {
		end = len(items)
	}

	return items[pagination.Offset:end]
}

func defaultRawJSON(value json.RawMessage, fallback string) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(fallback)
	}
	return value
}
