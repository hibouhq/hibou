package server

import (
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/auth"
)

// @Summary      Get current user
// @Description  Returns the authenticated user derived from the API key
// @Tags         users
// @Produce      json
// @Success      200  {object}  api.Response{data=store.User}
// @Failure      401  {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me [get]
func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	if user := UserFromContext(r.Context()); user != nil {
		api.JSON(w, http.StatusOK, user)
		return
	}
	// A service principal (ADR-022) has no user: identify the token.
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth.IsServicePrincipal() {
		api.JSON(w, http.StatusOK, map[string]any{
			"principal":  "service",
			"token_name": tokenAuth.Name,
			"owner_type": tokenAuth.OwnerType,
			"owner_id":   tokenAuth.OwnerID,
		})
		return
	}
	api.JSONError(w, http.StatusUnauthorized, "authentication required")
}
