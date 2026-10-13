package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/store"
)

type contextKey string

const (
	userContextKey      contextKey = "user"
	tokenAuthContextKey contextKey = "token_auth"
)

var ErrTokenScopeDenied = errors.New("token scope does not permit this action")

// Approval errors (ADR-022 amendment) are deliberately specific: a pending
// token is a real credential whose owner must ask an org admin to review it —
// never let that read as a bad or revoked key.
// ErrAccountNotAllowed refuses a session or user token whose account the
// sign-in allowlist no longer admits.
var ErrAccountNotAllowed = errors.New("this account is not allowed to use this instance")

// ErrTokenCreatorLeftOrg refuses an org-owned token whose creator is no
// longer a member of the org: they still hold the secret.
var ErrTokenCreatorLeftOrg = errors.New("token was created by someone who is no longer a member of its organization: ask an org admin to issue a new one")

var (
	ErrTokenPendingApproval = errors.New("token pending approval: ask an org admin to review it in Settings → API keys")
	ErrTokenRejected        = errors.New("token was rejected by an org admin: ask them to review it in Settings → API keys")
)

// approvalError maps a key's approval status to the error a request bearing
// it must receive, or nil when the key may authenticate.
func approvalError(apiKey *store.APIKey) error {
	switch apiKey.ApprovalStatus {
	case store.APIKeyApprovalPending:
		return ErrTokenPendingApproval
	case store.APIKeyApprovalRejected:
		return ErrTokenRejected
	}
	return nil
}

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

// IsServicePrincipal reports whether this token acts as its organization
// rather than as a user (ADR-022): org-owned tokens carry no request user —
// their org membership is ownership, their authority is the scope.
func (t *TokenAuth) IsServicePrincipal() bool {
	return t != nil && t.OwnerType == "org"
}

// IsMembershipWide reports whether this is a user's device-login token that
// reaches every org the user belongs to (ADR-043 §4). Its org access is the
// user's role, capped by each org's login-token policy.
func (t *TokenAuth) IsMembershipWide() bool {
	return t != nil && t.Scoped && !t.IsServicePrincipal() && t.Scope.MembershipWide()
}

// ActsForOrg reports whether a service principal belongs to the given org.
// False for user tokens — callers fall back to user membership then.
func (t *TokenAuth) ActsForOrg(orgID uuid.UUID) bool {
	return t.IsServicePrincipal() && t.OwnerID == orgID
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
				// A session the allowlist no longer admits is no session.
				if user, err := mgr.GetSessionUser(r, queries); err == nil && user != nil && mgr.UserAllowed(ctx, user) {
					ctx = WithUser(ctx, user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			user, apiKey, err := authenticateBearerToken(r, queries)
			if err == nil && apiKey != nil && !apiKey.IsOrgOwned() && !mgr.UserAllowed(ctx, user) {
				err = ErrAccountNotAllowed
			}
			// A pending/rejected token is answered here with its specific
			// message: the generic handler 401 would hide what the caller
			// must do (ask an org admin to review the token).
			if errors.Is(err, ErrTokenPendingApproval) || errors.Is(err, ErrTokenRejected) ||
				errors.Is(err, ErrTokenCreatorLeftOrg) || errors.Is(err, ErrAccountNotAllowed) {
				api.JSONError(w, http.StatusUnauthorized, err.Error())
				return
			}
			if err == nil && apiKey != nil {
				// Service principals (org-owned keys, ADR-022) carry no user:
				// the request acts as the org, and handlers authorize via
				// TokenAuth.ActsForOrg + the token scope.
				if user != nil && !apiKey.IsOrgOwned() {
					ctx = WithUser(ctx, user)
				}
				ctx = WithTokenAuth(ctx, TokenAuthForAPIKey(apiKey))
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *Manager) AuthenticateRequest(r *http.Request, queries *store.Queries) (*store.User, error) {
	if m != nil {
		if user, err := m.GetSessionUser(r, queries); err == nil && user != nil && m.UserAllowed(r.Context(), user) {
			return user, nil
		}
	}

	user, apiKey, err := authenticateBearerToken(r, queries)
	if err == nil && apiKey != nil && !apiKey.IsOrgOwned() && !m.UserAllowed(r.Context(), user) {
		return nil, ErrAccountNotAllowed
	}
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
	if apiKey == nil {
		return nil, nil, errors.New("invalid API key")
	}
	if err := ValidateAPIKey(apiKey, time.Now()); err != nil {
		return nil, nil, err
	}
	if err := TouchAPIKey(r.Context(), queries, apiKey); err != nil {
		return nil, nil, err
	}

	return apiKey.User, apiKey, nil
}

// ValidateAPIKey decides whether a stored key may authenticate. Shared by the
// HTTP middleware and the MCP transport so the two cannot drift.
//
// A user-owned key whose creator is gone is dead. An org-owned key is a
// service principal (ADR-022) and outlives a deleted creator by design, but
// not a creator who is still around and was removed from the org.
func ValidateAPIKey(apiKey *store.APIKey, now time.Time) error {
	if apiKey == nil {
		return errors.New("invalid API key")
	}
	if apiKey.User == nil && !apiKey.IsOrgOwned() {
		return errors.New("invalid API key")
	}
	if err := approvalError(apiKey); err != nil {
		return err
	}
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(now) {
		return errors.New("API key expired")
	}
	if apiKey.IsOrgOwned() && apiKey.CreatorLeftOrg {
		return ErrTokenCreatorLeftOrg
	}
	return nil
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
	if apiKey.UserID != nil {
		return *apiKey.UserID
	}
	return uuid.Nil
}
