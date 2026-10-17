package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

const (
	sessionCookieName    = "hibou_session"
	oauthStateCookieName = "hibou_oauth_state"
	// secureCookiePrefix pins a cookie to the exact host that set it: the
	// browser refuses it unless Secure, Path=/ and no Domain, so no sibling
	// subdomain can read or plant it.
	secureCookiePrefix = "__Host-"
	sessionMaxAge      = 7 * 24 * time.Hour
	oauthStateMaxAge   = 10 * time.Minute
)

// ErrSignInNotAllowed is returned by the OAuth callback when the sign-in
// allowlists are configured and the account matches none of them.
var ErrSignInNotAllowed = errors.New("this account is not allowed to sign in to this instance")

// Config holds authentication settings. Session cookies are always
// host-only (no Domain attribute).
type Config struct {
	SessionSecret string
	BaseURL       string
	CookieSecure  bool
	Providers     map[string]forge.Provider
	// Development enables /auth/dev-login (only when no provider is
	// configured either).
	Development bool
	// AllowedOrgs and AllowedUsers restrict sign-in and every later request
	// (session or user API key); both empty keeps it open. Entries are
	// compared case-insensitively. An AllowedUsers entry is a login or an
	// immutable "provider:id" (e.g. "github:583231"); logins are renamable,
	// so the id form is the safe one (see allowlist.go).
	AllowedOrgs  []string
	AllowedUsers []string
	Log          zerolog.Logger
}

// accountLoginer is implemented by forges that can name the token's user.
type accountLoginer interface {
	AccountLogin(ctx context.Context, token *oauth2.Token) (string, error)
}

// orgMembershipChecker is implemented by forges that can check org
// membership for the sign-in org allowlist (GitHub).
type orgMembershipChecker interface {
	IsOrgMember(ctx context.Context, token *oauth2.Token, login, org string) (bool, error)
}

// Manager handles authentication flows.
type Manager struct {
	cfg         Config
	queries     *store.Queries
	loginHooks  []func(ctx context.Context, user *store.User, providerID string, token *oauth2.Token)
	revokeHooks []func(userID uuid.UUID)
	allow       allowlistCache
}

func New(cfg Config, queries *store.Queries) *Manager {
	return &Manager{cfg: cfg, queries: queries}
}

func (m *Manager) AddLoginHook(hook func(ctx context.Context, user *store.User, providerID string, token *oauth2.Token)) {
	if hook == nil {
		return
	}
	m.loginHooks = append(m.loginHooks, hook)
}

// AddRevokeHook registers a callback run after a user's sessions are revoked
// (logout, administrator cut-off), e.g. to close their live websockets.
func (m *Manager) AddRevokeHook(hook func(userID uuid.UUID)) {
	if m == nil || hook == nil {
		return
	}
	m.revokeHooks = append(m.revokeHooks, hook)
}

func (m *Manager) BeginOAuthFlow(w http.ResponseWriter, r *http.Request, providerID string) error {
	provider, err := m.provider(providerID)
	if err != nil {
		return err
	}

	state, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("generate oauth state: %w", err)
	}
	// PKCE (RFC 7636): the verifier rides in the signed, HttpOnly state
	// cookie, so an intercepted authorization code is useless on its own.
	verifier := oauth2.GenerateVerifier()

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := m.sign(state, providerID, timestamp, verifier)

	// #nosec G124 -- cookie security attributes depend on deployment TLS config.
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(oauthStateCookieName),
		Value:    strings.Join([]string{hex.EncodeToString([]byte(state)), hex.EncodeToString([]byte(providerID)), hex.EncodeToString([]byte(timestamp)), hex.EncodeToString([]byte(verifier)), hex.EncodeToString(signature)}, "|"),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oauthStateMaxAge.Seconds()),
		Expires:  time.Now().Add(oauthStateMaxAge),
	})

	callbackURL := m.callbackURL(r, providerID)
	redirectURL := provider.OAuth2Config(callbackURL).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

func (m *Manager) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) (*store.User, error) {
	providerID := strings.TrimSpace(r.URL.Query().Get("provider"))
	provider, err := m.provider(providerID)
	if err != nil {
		return nil, err
	}

	stateCookie, err := r.Cookie(m.cookieName(oauthStateCookieName))
	if err != nil {
		return nil, fmt.Errorf("missing oauth state cookie: %w", err)
	}
	verifier, err := m.validateOAuthState(stateCookie.Value, providerID, strings.TrimSpace(r.URL.Query().Get("state")))
	if err != nil {
		return nil, err
	}
	m.clearCookie(w, oauthStateCookieName)

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		return nil, errors.New("missing oauth code")
	}

	token, err := provider.OAuth2Config(m.callbackURL(r, providerID)).Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange oauth code: %w", err)
	}

	info, err := provider.UserInfo(r.Context(), token)
	if err != nil {
		return nil, fmt.Errorf("load provider user info: %w", err)
	}
	if info == nil {
		return nil, errors.New("provider returned no user info")
	}
	if strings.TrimSpace(info.ProviderID) == "" {
		return nil, errors.New("provider user info missing provider id")
	}
	if strings.TrimSpace(info.Email) == "" {
		return nil, errors.New("provider user info missing email")
	}

	// Before any user row exists: a refused account leaves nothing behind.
	login, viaOrg, err := m.checkSignInAllowed(r.Context(), provider, token, provider.ID(), info.ProviderID)
	if err != nil {
		return nil, err
	}

	avatarURL := optionalString(info.AvatarURL)
	providerUser, err := m.queries.GetUserByProviderID(r.Context(), provider.ID(), info.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("lookup user by provider id: %w", err)
	}

	if providerUser == nil {
		providerUser, err = m.queries.CreateUser(r.Context(), info.Email, strings.TrimSpace(info.DisplayName), provider.ID(), info.ProviderID)
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
	}

	providerUser, err = m.queries.UpdateUser(r.Context(), providerUser.ID, info.Email, strings.TrimSpace(info.DisplayName), avatarURL)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	if providerUser == nil {
		return nil, errors.New("user disappeared during update")
	}
	m.recordSignIn(r.Context(), providerUser, login, viaOrg)

	m.invokeLoginHooks(r.Context(), providerUser, provider.ID(), token)

	return providerUser, nil
}

// checkSignInAllowed enforces the sign-in allowlists: with either configured,
// the account must be listed in AllowedUsers (login or provider:id) or be a
// member of an AllowedOrgs org. A forge that cannot answer (no login, no
// membership API) is refused. It returns the account login (looked up even
// without an allowlist, for later re-checks) and whether org membership is
// what admitted the account.
func (m *Manager) checkSignInAllowed(ctx context.Context, provider forge.Provider, token *oauth2.Token, providerName, providerUserID string) (string, bool, error) {
	login, canName, err := accountLogin(ctx, provider, token)
	if !m.Restricted() {
		if err != nil {
			m.cfg.Log.Warn().Err(err).Msg("could not load the forge login at sign-in")
		}
		return login, false, nil
	}
	if allowedUserEntry(m.cfg.AllowedUsers, providerName, providerUserID, "") {
		return login, false, nil
	}
	if !canName {
		return "", false, ErrSignInNotAllowed
	}
	if err != nil {
		return "", false, fmt.Errorf("load provider account login: %w", err)
	}
	if login == "" {
		return "", false, ErrSignInNotAllowed
	}
	if allowedUserEntry(m.cfg.AllowedUsers, providerName, providerUserID, login) {
		return login, false, nil
	}
	checker, ok := provider.(orgMembershipChecker)
	if !ok {
		return "", false, ErrSignInNotAllowed
	}
	for _, org := range m.cfg.AllowedOrgs {
		member, err := checker.IsOrgMember(ctx, token, login, org)
		if err != nil {
			m.cfg.Log.Warn().Err(err).Str("org", org).Str("login", login).Msg("sign-in allowlist: org membership check failed")
			continue
		}
		if member {
			return login, true, nil
		}
	}
	// Say why, or an operator only sees users bounced with nothing logged. A
	// GitHub App without Organization → Members: read sees only public
	// memberships, which reads as "not a member" here.
	m.cfg.Log.Info().Str("login", login).Strs("allowed_orgs", m.cfg.AllowedOrgs).
		Msg("sign-in allowlist: refused, not a member of any allowed org (GitHub App needs Organization → Members: read to see private memberships)")
	return "", false, ErrSignInNotAllowed
}

// recordSignIn stores what later requests are re-checked against: the forge
// login, and when org membership last admitted the user.
func (m *Manager) recordSignIn(ctx context.Context, user *store.User, login string, viaOrg bool) {
	if m.queries == nil {
		return
	}
	if login != "" {
		if err := m.queries.SetUserForgeLogin(ctx, user.ID, login); err != nil {
			m.cfg.Log.Warn().Err(err).Str("user_id", user.ID.String()).Msg("failed to record the forge login")
		} else {
			user.ForgeLogin = login
		}
	}
	if viaOrg {
		now := time.Now().UTC()
		if err := m.queries.SetUserSignInAllowedAt(ctx, user.ID, &now); err != nil {
			m.cfg.Log.Warn().Err(err).Str("user_id", user.ID.String()).Msg("failed to record the allowlist check")
		} else {
			user.SignInAllowedAt = &now
		}
	}
	m.forgetAllowed(user.ID)
}

// loginHookTimeout bounds one post-sign-in hook (the forge permission sync).
const loginHookTimeout = 5 * time.Minute

func (m *Manager) invokeLoginHooks(ctx context.Context, user *store.User, providerID string, token *oauth2.Token) {
	if len(m.loginHooks) == 0 || user == nil || token == nil {
		return
	}

	baseCtx := context.WithoutCancel(ctx)
	for _, hook := range m.loginHooks {
		if hook == nil {
			continue
		}
		h := hook
		tokenCopy := *token
		go func() {
			defer func() {
				_ = recover()
			}()
			// Detached from the request, but bounded: a hook waiting on a
			// forge that never answers must not live forever.
			hookCtx, cancel := context.WithTimeout(baseCtx, loginHookTimeout)
			defer cancel()
			h(hookCtx, user, providerID, &tokenCopy)
		}()
	}
}

func (m *Manager) SetSessionCookie(w http.ResponseWriter, user *store.User) {
	if user == nil {
		return
	}

	m.setSessionCookieAt(w, user, time.Now())
}

// setSessionCookieAt issues the session cookie as if signed at issued; tests
// use it to build aged sessions.
func (m *Manager) setSessionCookieAt(w http.ResponseWriter, user *store.User, issued time.Time) {
	timestamp := strconv.FormatInt(issued.Unix(), 10)
	userID := user.ID.String()
	epoch := strconv.FormatInt(user.SessionEpoch, 10)
	signature := m.sign(userID, epoch, timestamp)

	// #nosec G124 -- cookie security attributes depend on deployment TLS config.
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(sessionCookieName),
		Value:    strings.Join([]string{hex.EncodeToString([]byte(userID)), hex.EncodeToString([]byte(epoch)), hex.EncodeToString([]byte(timestamp)), hex.EncodeToString(signature)}, "|"),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
		Expires:  time.Now().Add(sessionMaxAge),
	})
}

// SessionIssuedAt reports when the request's session cookie was signed, after
// verifying the signature. Sensitive actions (approving a long-lived device
// token) use it to demand a recent sign-in; it does not check the epoch, so
// callers must also have authenticated the session normally.
func (m *Manager) SessionIssuedAt(r *http.Request) (time.Time, error) {
	cookie, err := r.Cookie(m.cookieName(sessionCookieName))
	if err != nil {
		return time.Time{}, err
	}
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 4 {
		return time.Time{}, errors.New("invalid session cookie format")
	}
	decoded := make([][]byte, len(parts))
	for i, part := range parts {
		if decoded[i], err = hex.DecodeString(part); err != nil {
			return time.Time{}, fmt.Errorf("decode session cookie: %w", err)
		}
	}
	if !hmac.Equal(decoded[3], m.sign(string(decoded[0]), string(decoded[1]), string(decoded[2]))) {
		return time.Time{}, errors.New("invalid session signature")
	}
	issuedAt, err := strconv.ParseInt(string(decoded[2]), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse session timestamp: %w", err)
	}
	return time.Unix(issuedAt, 0), nil
}

func (m *Manager) GetSessionUser(r *http.Request, queries *store.Queries) (*store.User, error) {
	cookie, err := r.Cookie(m.cookieName(sessionCookieName))
	if err != nil {
		return nil, err
	}

	// userID|epoch|timestamp|signature. Cookies signed before session epochs
	// existed have three parts and are rejected: their users sign in again.
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 4 {
		return nil, errors.New("invalid session cookie format")
	}

	userIDBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode session user id: %w", err)
	}
	epochBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode session epoch: %w", err)
	}
	timestampBytes, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode session timestamp: %w", err)
	}
	providedSig, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("decode session signature: %w", err)
	}

	userID := string(userIDBytes)
	epoch := string(epochBytes)
	timestamp := string(timestampBytes)
	if !hmac.Equal(providedSig, m.sign(userID, epoch, timestamp)) {
		return nil, errors.New("invalid session signature")
	}
	sessionEpoch, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse session epoch: %w", err)
	}

	issuedAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse session timestamp: %w", err)
	}
	if time.Since(time.Unix(issuedAt, 0)) > sessionMaxAge {
		return nil, errors.New("session expired")
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("parse session user id: %w", err)
	}

	activeQueries := queries
	if activeQueries == nil {
		activeQueries = m.queries
	}
	if activeQueries == nil {
		return nil, errors.New("queries not configured")
	}

	user, err := activeQueries.GetUserByID(r.Context(), parsedUserID)
	if err != nil {
		return nil, fmt.Errorf("load session user: %w", err)
	}
	if user == nil {
		return nil, errors.New("session user not found")
	}
	if user.SessionEpoch != sessionEpoch {
		return nil, errors.New("session revoked")
	}

	return user, nil
}

func (m *Manager) ClearSession(w http.ResponseWriter) {
	m.clearCookie(w, sessionCookieName)
}

// RevokeSessions invalidates every session cookie issued to the user so far
// (logout, or an administrator cutting off access).
func (m *Manager) RevokeSessions(ctx context.Context, userID uuid.UUID) error {
	if m == nil || m.queries == nil {
		return errors.New("queries not configured")
	}
	if _, err := m.queries.BumpUserSessionEpoch(ctx, userID); err != nil {
		return err
	}
	for _, hook := range m.revokeHooks {
		hook(userID)
	}
	return nil
}

// HasSessionCookie reports whether the request carries a session cookie under
// either name (Secure "__Host-" or plain). SessionAuth prefers a session
// over a bearer token, so CSRF protection may only waive its checks when no
// such cookie rides along.
func HasSessionCookie(r *http.Request) bool {
	for _, name := range []string{secureCookiePrefix + sessionCookieName, sessionCookieName} {
		if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
			return true
		}
	}
	return false
}

// cookieName returns the cookie name in use: "__Host-"-prefixed when cookies
// are Secure (HTTPS base URL). Plain-HTTP development keeps the bare name,
// which browsers would otherwise refuse.
func (m *Manager) cookieName(name string) string {
	if m.cfg.CookieSecure {
		return secureCookiePrefix + name
	}
	return name
}

func (m *Manager) provider(providerID string) (forge.Provider, error) {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return nil, errors.New("provider is required")
	}

	provider, ok := m.cfg.Providers[providerID]
	if !ok || provider == nil {
		return nil, fmt.Errorf("provider %q is not configured", providerID)
	}

	return provider, nil
}

func (m *Manager) callbackURL(r *http.Request, providerID string) string {
	if m.cfg.BaseURL != "" {
		return fmt.Sprintf("%s/api/v1/auth/callback?provider=%s", strings.TrimRight(m.cfg.BaseURL, "/"), providerID)
	}

	scheme := "http"
	if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}

	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}

	return fmt.Sprintf("%s://%s/api/v1/auth/callback?provider=%s", scheme, host, providerID)
}

// validateOAuthState checks the signed state cookie against the callback and
// returns the PKCE verifier it carries.
func (m *Manager) validateOAuthState(cookieValue, providerID, state string) (string, error) {
	parts := strings.Split(cookieValue, "|")
	if len(parts) != 5 {
		return "", errors.New("invalid oauth state cookie format")
	}

	decoded := make([]string, len(parts))
	for i, part := range parts {
		value, err := hex.DecodeString(part)
		if err != nil {
			return "", fmt.Errorf("decode oauth state cookie: %w", err)
		}
		decoded[i] = string(value)
	}
	storedState, storedProviderID, timestamp, verifier := decoded[0], decoded[1], decoded[2], decoded[3]
	providedSig := []byte(decoded[4])

	if storedProviderID != providerID {
		return "", errors.New("oauth provider mismatch")
	}
	if storedState != state {
		return "", errors.New("oauth state mismatch")
	}
	if !hmac.Equal(providedSig, m.sign(storedState, storedProviderID, timestamp, verifier)) {
		return "", errors.New("oauth state signature mismatch")
	}

	issuedAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse oauth timestamp: %w", err)
	}
	if time.Since(time.Unix(issuedAt, 0)) > oauthStateMaxAge {
		return "", errors.New("oauth state expired")
	}

	return verifier, nil
}

func (m *Manager) sign(parts ...string) []byte {
	mac := hmac.New(sha256.New, []byte(m.cfg.SessionSecret))
	_, _ = mac.Write([]byte(strings.Join(parts, "|")))
	return mac.Sum(nil)
}

func (m *Manager) clearCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- cookie security attributes depend on deployment TLS config.
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(name),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func optionalString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
