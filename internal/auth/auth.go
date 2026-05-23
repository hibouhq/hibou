package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/forge"
	"github.com/hibouhq/lehibou/internal/store"
)

const (
	sessionCookieName    = "hibou_session"
	oauthStateCookieName = "hibou_oauth_state"
	sessionMaxAge        = 7 * 24 * time.Hour
	oauthStateMaxAge     = 10 * time.Minute
)

// Config holds authentication settings.
type Config struct {
	SessionSecret string
	CookieDomain  string
	CookieSecure  bool
	Providers     map[string]forge.Provider
}

// Manager handles authentication flows.
type Manager struct {
	cfg     Config
	queries *store.Queries
}

func New(cfg Config, queries *store.Queries) *Manager {
	return &Manager{cfg: cfg, queries: queries}
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

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := m.sign(state, providerID, timestamp)

	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    strings.Join([]string{hex.EncodeToString([]byte(state)), hex.EncodeToString([]byte(providerID)), hex.EncodeToString([]byte(timestamp)), hex.EncodeToString(signature)}, "|"),
		Path:     "/",
		Domain:   m.cfg.CookieDomain,
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oauthStateMaxAge.Seconds()),
		Expires:  time.Now().Add(oauthStateMaxAge),
	})

	redirectURL := provider.OAuth2Config(m.callbackURL(r, providerID)).AuthCodeURL(state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

func (m *Manager) HandleOAuthCallback(w http.ResponseWriter, r *http.Request) (*store.User, error) {
	providerID := strings.TrimSpace(r.URL.Query().Get("provider"))
	provider, err := m.provider(providerID)
	if err != nil {
		return nil, err
	}

	stateCookie, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		return nil, fmt.Errorf("missing oauth state cookie: %w", err)
	}
	if err := m.validateOAuthState(stateCookie.Value, providerID, strings.TrimSpace(r.URL.Query().Get("state"))); err != nil {
		return nil, err
	}
	m.clearCookie(w, oauthStateCookieName)

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		return nil, fmt.Errorf("missing oauth code")
	}

	token, err := provider.OAuth2Config(m.callbackURL(r, providerID)).Exchange(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("exchange oauth code: %w", err)
	}

	info, err := provider.UserInfo(r.Context(), token)
	if err != nil {
		return nil, fmt.Errorf("load provider user info: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("provider returned no user info")
	}
	if strings.TrimSpace(info.ProviderID) == "" {
		return nil, fmt.Errorf("provider user info missing provider id")
	}
	if strings.TrimSpace(info.Email) == "" {
		return nil, fmt.Errorf("provider user info missing email")
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
		return nil, fmt.Errorf("user disappeared during update")
	}

	return providerUser, nil
}

func (m *Manager) SetSessionCookie(w http.ResponseWriter, user *store.User) {
	if user == nil {
		return
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	userID := user.ID.String()
	signature := m.sign(userID, timestamp)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    strings.Join([]string{hex.EncodeToString([]byte(userID)), hex.EncodeToString([]byte(timestamp)), hex.EncodeToString(signature)}, "|"),
		Path:     "/",
		Domain:   m.cfg.CookieDomain,
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionMaxAge.Seconds()),
		Expires:  time.Now().Add(sessionMaxAge),
	})
}

func (m *Manager) GetSessionUser(r *http.Request, queries *store.Queries) (*store.User, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid session cookie format")
	}

	userIDBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode session user id: %w", err)
	}
	timestampBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode session timestamp: %w", err)
	}
	providedSig, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode session signature: %w", err)
	}

	userID := string(userIDBytes)
	timestamp := string(timestampBytes)
	if !hmac.Equal(providedSig, m.sign(userID, timestamp)) {
		return nil, fmt.Errorf("invalid session signature")
	}

	issuedAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse session timestamp: %w", err)
	}
	if time.Since(time.Unix(issuedAt, 0)) > sessionMaxAge {
		return nil, fmt.Errorf("session expired")
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
		return nil, fmt.Errorf("queries not configured")
	}

	user, err := activeQueries.GetUserByID(r.Context(), parsedUserID)
	if err != nil {
		return nil, fmt.Errorf("load session user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("session user not found")
	}

	return user, nil
}

func (m *Manager) ClearSession(w http.ResponseWriter) {
	m.clearCookie(w, sessionCookieName)
}

func (m *Manager) provider(providerID string) (forge.Provider, error) {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return nil, fmt.Errorf("provider is required")
	}

	provider, ok := m.cfg.Providers[providerID]
	if !ok || provider == nil {
		return nil, fmt.Errorf("provider %q is not configured", providerID)
	}

	return provider, nil
}

func (m *Manager) callbackURL(r *http.Request, providerID string) string {
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

	return fmt.Sprintf("%s://%s/auth/callback?provider=%s", scheme, host, providerID)
	}

func (m *Manager) validateOAuthState(cookieValue, providerID, state string) error {
	parts := strings.Split(cookieValue, "|")
	if len(parts) != 4 {
		return fmt.Errorf("invalid oauth state cookie format")
	}

	stateBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode oauth state: %w", err)
	}
	providerBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode oauth provider: %w", err)
	}
	timestampBytes, err := hex.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode oauth timestamp: %w", err)
	}
	providedSig, err := hex.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("decode oauth signature: %w", err)
	}

	storedState := string(stateBytes)
	storedProviderID := string(providerBytes)
	timestamp := string(timestampBytes)
	if storedProviderID != providerID {
		return fmt.Errorf("oauth provider mismatch")
	}
	if storedState != state {
		return fmt.Errorf("oauth state mismatch")
	}
	if !hmac.Equal(providedSig, m.sign(storedState, storedProviderID, timestamp)) {
		return fmt.Errorf("oauth state signature mismatch")
	}

	issuedAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("parse oauth timestamp: %w", err)
	}
	if time.Since(time.Unix(issuedAt, 0)) > oauthStateMaxAge {
		return fmt.Errorf("oauth state expired")
	}

	return nil
}

func (m *Manager) sign(parts ...string) []byte {
	mac := hmac.New(sha256.New, []byte(m.cfg.SessionSecret))
	_, _ = mac.Write([]byte(strings.Join(parts, "|")))
	return mac.Sum(nil)
}

func (m *Manager) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Domain:   m.cfg.CookieDomain,
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