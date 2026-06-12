package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/store"
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
				if user, err := mgr.AuthenticateRequest(r, queries); err == nil && user != nil {
					ctx = WithUser(ctx, user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			} else if user, err := authenticateBearerToken(r, queries); err == nil && user != nil {
				ctx = WithUser(ctx, user)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *Manager) AuthenticateRequest(r *http.Request, queries *store.Queries) (*store.User, error) {
	if m != nil {
		if user, err := m.GetSessionUser(r, queries); err == nil && user != nil {
			return user, nil
		}
	}

	return authenticateBearerToken(r, queries)
}

func authenticateBearerToken(r *http.Request, queries *store.Queries) (*store.User, error) {
	if queries == nil {
		return nil, errors.New("queries not configured")
	}

	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, nil
	}

	key := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	if key == "" {
		return nil, errors.New("missing bearer token")
	}

	apiKey, err := queries.GetAPIKeyByHash(r.Context(), store.HashAPIKey(key))
	if err != nil {
		return nil, err
	}
	if apiKey == nil || apiKey.User == nil {
		return nil, errors.New("invalid API key")
	}
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("API key expired")
	}

	if err := queries.UpdateAPIKeyLastUsed(r.Context(), apiKey.ID); err != nil {
		return nil, err
	}

	return apiKey.User, nil
}
