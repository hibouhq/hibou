package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/lehibou/internal/store"
)

type contextKey string

const userContextKey contextKey = "user"

func WithUser(ctx context.Context, user *store.User) context.Context {
	if user == nil {
		return ctx
	}

	return context.WithValue(ctx, userContextKey, user)
}

func UserFromContext(ctx context.Context) *store.User {
	user, ok := ctx.Value(userContextKey).(*store.User)
	if !ok {
		return nil
	}

	return user
}

// SessionAuth returns middleware that checks for a valid session cookie or API key.
// It sets the user in context if found but does NOT reject unauthenticated requests
// (route handlers decide if auth is required).
func SessionAuth(mgr *Manager, queries *store.Queries) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if mgr != nil {
				if user, err := mgr.GetSessionUser(r, queries); err == nil && user != nil {
					ctx = WithUser(ctx, user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			authorization := r.Header.Get("Authorization")
			if strings.HasPrefix(authorization, "Bearer ") && queries != nil {
				key := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
				if key != "" {
					apiKey, err := queries.GetAPIKeyByHash(r.Context(), store.HashAPIKey(key))
					if err == nil && apiKey != nil && apiKey.User != nil {
						if apiKey.ExpiresAt == nil || apiKey.ExpiresAt.After(time.Now()) {
							_ = queries.UpdateAPIKeyLastUsed(r.Context(), apiKey.ID)
							ctx = WithUser(ctx, apiKey.User)
						}
					}
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}