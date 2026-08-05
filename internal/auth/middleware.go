package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/store"
)

type contextKey string

const (
	userContextKey      contextKey = "user"
	tokenAuthContextKey contextKey = "token_auth"
)

var ErrTokenScopeDenied = errors.New("token scope does not permit this action")

// TokenAuth carries a bearer token's resolved scope for request authorization,
// plus the identity a token-authored record is attributed to (ADR-020 finding
// provenance). Name and owner are captured here at authentication time so
// provenance costs no extra query and survives the key being revoked later.
type TokenAuth struct {
	KeyID     uuid.UUID
	Name      string
	OwnerType string
	OwnerID   uuid.UUID
	Scope     apitoken.Scope
	Scoped    bool
}

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

// WithTokenAuth attaches bearer token authorization to a request context.
func WithTokenAuth(ctx context.Context, tokenAuth *TokenAuth) context.Context {
	if tokenAuth == nil {
		return ctx
	}

	return context.WithValue(ctx, tokenAuthContextKey, tokenAuth)
}

// TokenAuthFromContext returns bearer token authorization from a request context.
func TokenAuthFromContext(ctx context.Context) *TokenAuth {
	tokenAuth, ok := ctx.Value(tokenAuthContextKey).(*TokenAuth)
	if !ok {
		return nil
	}

	return tokenAuth
}

// RequireCapability verifies scoped bearer token access to a resource.
func RequireCapability(ctx context.Context, cap apitoken.Capability, need apitoken.AccessLevel, org, repoSlug string) error {
	tokenAuth := TokenAuthFromContext(ctx)
	if tokenAuth == nil || !tokenAuth.Scoped || tokenAuth.Scope.Allows(cap, need, org, repoSlug) {
		return nil
	}

	return ErrTokenScopeDenied
}

// RequireOrgWideCapability verifies scoped bearer token access across every
// repository in an organization.
func RequireOrgWideCapability(ctx context.Context, cap apitoken.Capability, need apitoken.AccessLevel, org string) error {
	tokenAuth := TokenAuthFromContext(ctx)
	if tokenAuth == nil || !tokenAuth.Scoped || tokenAuth.Scope.AllowsOrgWide(cap, need, org) {
		return nil
	}

	return ErrTokenScopeDenied
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

			if user, apiKey, err := authenticateBearerToken(r, queries); err == nil && user != nil {
				ctx = WithUser(ctx, user)
				ctx = WithTokenAuth(ctx, TokenAuthForAPIKey(apiKey))
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

	user, _, err := authenticateBearerToken(r, queries)
	return user, err
}

func authenticateBearerToken(r *http.Request, queries *store.Queries) (*store.User, *store.APIKey, error) {
	if queries == nil {
		return nil, nil, errors.New("queries not configured")
	}

	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, nil, nil
	}

	key := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	if key == "" {
		return nil, nil, errors.New("missing bearer token")
	}

	apiKey, err := queries.GetAPIKeyByHash(r.Context(), store.HashAPIKey(key))
	if err != nil {
		return nil, nil, err
	}
	if apiKey == nil || apiKey.User == nil {
		return nil, nil, errors.New("invalid API key")
	}
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, nil, errors.New("API key expired")
	}
	if err := TouchAPIKey(r.Context(), queries, apiKey); err != nil {
		return nil, nil, err
	}

	return apiKey.User, apiKey, nil
}

// lastUsedResolution bounds last_used_at write amplification: an agent polling
// every few seconds must not turn authentication into one hot-row UPDATE per
// request. "Last used" is a staleness signal read at human resolution; five
// minutes loses nothing.
const lastUsedResolution = 5 * time.Minute

// TouchAPIKey records that a key was just used, skipping the write when the
// stored timestamp is already fresh.
func TouchAPIKey(ctx context.Context, queries *store.Queries, apiKey *store.APIKey) error {
	if apiKey.LastUsedAt != nil && time.Since(*apiKey.LastUsedAt) < lastUsedResolution {
		return nil
	}
	return queries.UpdateAPIKeyLastUsed(ctx, apiKey.ID)
}

// TokenAuthForAPIKey resolves a stored key to the authorization + attribution
// attached to its requests. Shared by the HTTP middleware and the MCP
// transport so the two can never drift.
func TokenAuthForAPIKey(apiKey *store.APIKey) *TokenAuth {
	if apiKey == nil {
		return nil
	}

	tokenAuth := &TokenAuth{
		KeyID:     apiKey.ID,
		Name:      apiKey.Name,
		OwnerType: apiKeyOwnerType(apiKey),
		OwnerID:   apiKeyOwnerID(apiKey),
		Scoped:    apiKey.HasScope(),
	}
	// A malformed scope stays scoped with the zero scope, which denies
	// everything — never fall back to unscoped full access.
	if scope, err := apiKey.Scope(); err == nil {
		tokenAuth.Scope = scope
	}
	return tokenAuth
}

func apiKeyOwnerType(apiKey *store.APIKey) string {
	if apiKey.OwnerType == "org" {
		return "org"
	}
	return "user"
}

// apiKeyOwnerID falls back to the key's user for legacy rows minted before
// ownership existed, so every token always names an accountable principal.
func apiKeyOwnerID(apiKey *store.APIKey) uuid.UUID {
	if apiKey.OwnerID != nil {
		return *apiKey.OwnerID
	}
	return apiKey.UserID
}
