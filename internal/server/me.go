package server

import (
	"net/http"

	"github.com/hibouhq/lehibou/internal/api"
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
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	api.JSON(w, http.StatusOK, user)
}
