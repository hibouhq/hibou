package server

import (
	"context"
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

func UserFromContext(ctx context.Context) *store.User {
	return internalauth.UserFromContext(ctx)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.authMgr == nil {
		api.JSONError(w, http.StatusInternalServerError, "auth manager is not configured")
		return
	}

	user, err := s.authMgr.HandleOAuthCallback(w, r)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.orgProvisionSvc != nil {
		if err := s.orgProvisionSvc.ClaimPendingAdmin(r.Context(), user); err != nil {
			s.log.Error().Err(err).Str("user_id", user.ID.String()).Msg("failed to claim pending forge org admin memberships")
		}
	}

	s.authMgr.SetSessionCookie(w, user)
	http.Redirect(w, r, "/", http.StatusFound)
}
