package auth

import (
	"net/http"
	"sort"
	"strings"

	"github.com/hibouhq/lehibou/internal/api"
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
			api.JSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		mgr.SetSessionCookie(w, user)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// @Summary      Logout
// @Description  Clears the current session cookie
// @Tags         auth
// @Success      204  "No Content"
// @Router       /auth/logout [post]
func LogoutHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mgr != nil {
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
// @Description  Creates or fetches a local admin user for development. Only available when no forge providers are configured.
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
		if len(mgr.cfg.Providers) > 0 {
			api.JSONError(w, http.StatusForbidden, "dev login is disabled when forge providers are configured")
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