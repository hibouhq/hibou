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

	user, returnPath, err := s.authMgr.HandleOAuthCallback(w, r)
	if err != nil {
		internalauth.WriteCallbackError(w, r, s.authMgr, err)
		return
	}
	if s.orgProvisionSvc != nil {
		if err := s.orgProvisionSvc.ClaimPendingAdmin(r.Context(), user); err != nil {
			s.log.Error().Err(err).Str("user_id", user.ID.String()).Msg("failed to claim pending forge org admin memberships")
		}
	}

	s.authMgr.SetSessionCookie(w, user)
	// #nosec G710 -- returnPath comes from SafeReturnPath: only /device, rebuilt from parsed parts.
	http.Redirect(w, r, returnPath, http.StatusFound)
}
