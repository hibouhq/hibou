package auth

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
)

type providerResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// @Summary      Begin login
// @Description  Redirects the caller to the selected OAuth provider login flow
// @Tags         auth
// @Param        provider  query     string  true  "Provider ID"
// @Success      302       "Found"
// @Failure      400       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Router       /auth/login [get]
func LoginHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mgr == nil {
			api.JSONError(w, http.StatusInternalServerError, "auth manager is not configured")
			return
		}

		if err := mgr.BeginOAuthFlow(w, r, strings.TrimSpace(r.URL.Query().Get("provider"))); err != nil {
			api.JSONError(w, http.StatusBadRequest, err.Error())
		}
	}
}

// @Summary      Handle login callback
// @Description  Exchanges the OAuth callback code, upserts the user, sets the session cookie, and redirects home
// @Tags         auth
// @Param        provider  query     string  true  "Provider ID"
// @Param        code      query     string  true  "OAuth authorization code"
// @Param        state     query     string  true  "OAuth state"
// @Success      302       "Found"
// @Failure      400       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Router       /auth/callback [get]
func CallbackHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mgr == nil {
			api.JSONError(w, http.StatusInternalServerError, "auth manager is not configured")
			return
		}

		user, err := mgr.HandleOAuthCallback(w, r)
		if err != nil {
			WriteCallbackError(w, r, mgr, err)
			return
		}

		mgr.SetSessionCookie(w, user)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// Sign-in failure codes the login page turns into a message. The browser
// arrives here by navigation, so a JSON body would be shown raw; the page
// maps the code to fixed text and never renders anything from the URL.
const (
	CallbackErrorNotAllowed = "not_allowed"
	CallbackErrorFailed     = "sign_in_failed"
)

// WriteCallbackError answers a failed OAuth callback by sending the browser
// back to the login page with a failure code. The detail (provider responses,
// state mismatches) is logged, never echoed: the caller learns only that
// sign-in failed, or that their account is not allowed.
func WriteCallbackError(w http.ResponseWriter, r *http.Request, mgr *Manager, err error) {
	code := CallbackErrorFailed
	if errors.Is(err, ErrSignInNotAllowed) {
		code = CallbackErrorNotAllowed
	} else if mgr != nil {
		mgr.cfg.Log.Warn().Err(err).Msg("oauth callback failed")
	}
	http.Redirect(w, r, "/login?error="+code, http.StatusFound)
}

// @Summary      Logout
// @Description  Revokes every session of the current user and clears the session cookie
// @Tags         auth
// @Success      204  "No Content"
// @Router       /auth/logout [post]
func LogoutHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mgr != nil {
			// Clearing the cookie alone leaves a copied cookie valid until it
			// expires; bumping the epoch kills it server-side.
			if user, err := mgr.GetSessionUser(r, nil); err == nil && user != nil {
				if err := mgr.RevokeSessions(r.Context(), user.ID); err != nil {
					mgr.cfg.Log.Error().Err(err).Str("user_id", user.ID.String()).Msg("failed to revoke sessions on logout")
					api.JSONError(w, http.StatusInternalServerError, "failed to log out")
					return
				}
			}
			mgr.ClearSession(w)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// @Summary      List auth providers
// @Description  Returns the configured authentication providers
// @Tags         auth
// @Produce      json
// @Success      200  {object}  api.Response{data=[]auth.providerResponse}
// @Router       /auth/providers [get]
func ProvidersHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mgr == nil {
			api.JSON(w, http.StatusOK, []providerResponse{})
			return
		}

		ids := make([]string, 0, len(mgr.cfg.Providers))
		for id := range mgr.cfg.Providers {
			ids = append(ids, id)
		}
		sort.Strings(ids)

		providers := make([]providerResponse, 0, len(ids))
		for _, id := range ids {
			providers = append(providers, providerResponse{
				ID:   id,
				Name: providerName(id),
			})
		}

		api.JSON(w, http.StatusOK, providers)
	}
}

// @Summary      Dev login
// @Description  Creates or fetches a local admin user for development. Only available in development mode with no forge providers configured.
// @Tags         auth
// @Produce      json
// @Success      302  "Found"
// @Failure      403  {object}  api.Response
// @Failure      500  {object}  api.Response
// @Router       /auth/dev-login [post]
func DevLoginHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mgr == nil {
			api.JSONError(w, http.StatusInternalServerError, "auth manager is not configured")
			return
		}
		if !mgr.DevLoginEnabled() {
			api.JSONError(w, http.StatusForbidden, "dev login is only available in development mode with no forge providers configured")
			return
		}

		user, err := mgr.queries.GetUserByProviderID(r.Context(), "local", "dev-admin")
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to lookup dev user")
			return
		}
		if user == nil {
			user, err = mgr.queries.CreateUser(r.Context(), "admin@localhost", "Dev Admin", "local", "dev-admin")
			if err != nil {
				api.JSONError(w, http.StatusInternalServerError, "failed to create dev user")
				return
			}
		}

		mgr.SetSessionCookie(w, user)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// DevLoginEnabled reports whether /auth/dev-login may mint a session: only
// in development, and only when no forge provider is configured.
func (m *Manager) DevLoginEnabled() bool {
	return m != nil && m.cfg.Development && len(m.cfg.Providers) == 0
}

func providerName(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "github":
		return "GitHub"
	case "gitlab":
		return "GitLab"
	case "gitea":
		return "Gitea"
	case "forgejo":
		return "Forgejo"
	default:
		if id == "" {
			return ""
		}
		return strings.ToUpper(id[:1]) + id[1:]
	}
}
