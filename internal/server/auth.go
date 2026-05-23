package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/lehibou/internal/api"
	internalauth "github.com/hibouhq/lehibou/internal/auth"
	"github.com/hibouhq/lehibou/internal/store"
)

func apiKeyAuth(queries *store.Queries) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorization := r.Header.Get("Authorization")
			if !strings.HasPrefix(authorization, "Bearer ") {
				api.JSONError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}

			key := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
			if key == "" {
				api.JSONError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}

			apiKey, err := queries.GetAPIKeyByHash(r.Context(), store.HashAPIKey(key))
			if err != nil {
				api.JSONError(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			if apiKey == nil || apiKey.User == nil {
				api.JSONError(w, http.StatusUnauthorized, "invalid API key")
				return
			}
			if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
				api.JSONError(w, http.StatusUnauthorized, "API key expired")
				return
			}

			if err := queries.UpdateAPIKeyLastUsed(r.Context(), apiKey.ID); err != nil {
				api.JSONError(w, http.StatusUnauthorized, "invalid API key")
				return
			}

			ctx := internalauth.WithUser(r.Context(), apiKey.User)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserFromContext(ctx context.Context) *store.User {
	return internalauth.UserFromContext(ctx)
}
