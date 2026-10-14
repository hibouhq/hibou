package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

const testSessionSecret = "0123456789abcdef0123456789abcdef" // gitleaks:allow -- this is a test file

// fakeLoginProvider implements just enough of forge.Provider for the OAuth
// flow and the sign-in allowlist; any other call panics on the nil embed.
type fakeLoginProvider struct {
	forge.Provider
	login   string
	members map[string]bool
}

func (p *fakeLoginProvider) ID() string { return "github" }

func (p *fakeLoginProvider) OAuth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    "client",
		RedirectURL: redirectURL,
		Endpoint:    oauth2.Endpoint{AuthURL: "https://forge.example.com/authorize", TokenURL: "https://forge.example.com/token"},
	}
}

func (p *fakeLoginProvider) AccountLogin(context.Context, *oauth2.Token) (string, error) {
	return p.login, nil
}

func (p *fakeLoginProvider) IsOrgMember(_ context.Context, _ *oauth2.Token, _ string, org string) (bool, error) {
	return p.members[org], nil
}

// loginOnlyProvider can name its user but not check org membership (the
// GitLab / Forgejo shape).
type loginOnlyProvider struct {
	forge.Provider
	login string
}

func (p *loginOnlyProvider) AccountLogin(context.Context, *oauth2.Token) (string, error) {
	return p.login, nil
}

// A12: the authorization request carries a PKCE S256 challenge and the
// verifier is bound into the signed state cookie.
func TestBeginOAuthFlowUsesPKCE(t *testing.T) {
	t.Parallel()

	mgr := New(Config{SessionSecret: testSessionSecret, BaseURL: "https://hibou.example.com", CookieSecure: true,
		Providers: map[string]forge.Provider{"github": &fakeLoginProvider{}}}, nil)
	recorder := httptest.NewRecorder()
	if err := mgr.BeginOAuthFlow(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/auth/login?provider=github", nil), "github"); err != nil {
		t.Fatalf("BeginOAuthFlow: %v", err)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	query := location.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("redirect lacks a PKCE S256 challenge: %s", location)
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-hibou_oauth_state" || cookies[0].Domain != "" || !cookies[0].Secure {
		t.Fatalf("state cookie = %+v, want one host-only __Host- Secure cookie", cookies)
	}
	verifier, err := mgr.validateOAuthState(cookies[0].Value, "github", query.Get("state"))
	if err != nil || verifier == "" {
		t.Fatalf("validateOAuthState = %q, %v", verifier, err)
	}
	if oauth2.S256ChallengeFromVerifier(verifier) != query.Get("code_challenge") {
		t.Fatal("cookie verifier does not match the challenge sent to the provider")
	}

	// A tampered verifier breaks the signature.
	parts := strings.Split(cookies[0].Value, "|")
	parts[3] = "00"
	if _, err := mgr.validateOAuthState(strings.Join(parts, "|"), "github", query.Get("state")); err == nil {
		t.Fatal("tampered verifier must fail validation")
	}
}

// A5: plain-HTTP development keeps the unprefixed cookie name (browsers
// refuse __Host- without Secure), and no cookie ever carries a Domain.
func TestSessionCookieIsHostOnly(t *testing.T) {
	t.Parallel()

	for _, secure := range []bool{false, true} {
		mgr := New(Config{SessionSecret: testSessionSecret, CookieSecure: secure}, nil)
		recorder := httptest.NewRecorder()
		mgr.SetSessionCookie(recorder, &store.User{ID: uuid.New()})
		cookies := recorder.Result().Cookies()
		want := "hibou_session"
		if secure {
			want = "__Host-hibou_session"
		}
		if len(cookies) != 1 || cookies[0].Name != want || cookies[0].Domain != "" || cookies[0].Path != "/" {
			t.Fatalf("secure=%v: cookie = %+v, want host-only %q", secure, cookies, want)
		}
	}
}

// §4.1: with an allowlist configured, only listed users or members of a
// listed org get through; a forge that cannot answer is refused.
func TestCheckSignInAllowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	token := &oauth2.Token{AccessToken: "t"}
	open := New(Config{}, nil)
	if _, _, err := open.checkSignInAllowed(ctx, &loginOnlyProvider{login: "anyone"}, token, "github", "1"); err != nil {
		t.Fatalf("no allowlist must keep sign-in open, got %v", err)
	}

	mgr := New(Config{AllowedUsers: []string{"Octocat"}, AllowedOrgs: []string{"hibouhq"}}, nil)
	cases := []struct {
		name     string
		provider forge.Provider
		allowed  bool
	}{
		{"listed user (case-insensitive)", &fakeLoginProvider{login: "octocat"}, true},
		{"member of listed org", &fakeLoginProvider{login: "dev", members: map[string]bool{"hibouhq": true}}, true},
		{"member of another org", &fakeLoginProvider{login: "squatter", members: map[string]bool{"elsewhere": true}}, false},
		{"listed user on a forge without membership API", &loginOnlyProvider{login: "octocat"}, true},
		{"unlisted user on a forge without membership API", &loginOnlyProvider{login: "dev"}, false},
	}
	for _, tc := range cases {
		_, _, err := mgr.checkSignInAllowed(ctx, tc.provider, token, "github", "1")
		if tc.allowed && err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
		if !tc.allowed && !errors.Is(err, ErrSignInNotAllowed) {
			t.Errorf("%s: err = %v, want ErrSignInNotAllowed", tc.name, err)
		}
	}
}

// A3: dev login needs development mode AND no provider.
func TestDevLoginEnabled(t *testing.T) {
	t.Parallel()

	providers := map[string]forge.Provider{"github": &fakeLoginProvider{}}
	for _, tc := range []struct {
		cfg  Config
		want bool
	}{
		{Config{}, false},
		{Config{Development: true}, true},
		{Config{Development: true, Providers: providers}, false},
		{Config{Providers: providers}, false},
	} {
		if got := New(tc.cfg, nil).DevLoginEnabled(); got != tc.want {
			t.Errorf("DevLoginEnabled(dev=%v, providers=%d) = %v, want %v", tc.cfg.Development, len(tc.cfg.Providers), got, tc.want)
		}
	}

	recorder := httptest.NewRecorder()
	DevLoginHandler(New(Config{}, nil))(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/dev-login", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("dev login outside development: status %d, want 403", recorder.Code)
	}
}

// A12: the callback never echoes the underlying error; the browser is sent
// back to the login page with a fixed failure code.
func TestWriteCallbackErrorIsGeneric(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?provider=github", nil)
	recorder := httptest.NewRecorder()
	WriteCallbackError(recorder, request, New(Config{}, nil), errors.New("exchange oauth code: oauth2: server response missing access_token secret-detail"))
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/login?error=sign_in_failed" {
		t.Fatalf("failed callback = %d %q, want 302 to /login?error=sign_in_failed", recorder.Code, recorder.Header().Get("Location"))
	}
	if strings.Contains(recorder.Body.String()+recorder.Header().Get("Location"), "secret-detail") {
		t.Fatalf("callback error leaked detail: %s", recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	WriteCallbackError(recorder, request, nil, ErrSignInNotAllowed)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/login?error=not_allowed" {
		t.Fatalf("not-allowed callback = %d %q, want 302 to /login?error=not_allowed", recorder.Code, recorder.Header().Get("Location"))
	}
}

// A4: logout bumps the user's session epoch, so a copy of the cookie taken
// before logout stops authenticating; pre-epoch (3-part) cookies are refused.
func TestLogoutRevokesOutstandingSessions(t *testing.T) {
	t.Parallel()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Skipf("migrate database: %v", err)
	}
	queries := store.NewQueries(db)
	ctx := context.Background()
	user, err := queries.CreateUser(ctx, uuid.NewString()+"@example.com", "Epoch User", "github", uuid.NewString())
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	mgr := New(Config{SessionSecret: testSessionSecret}, queries)
	login := httptest.NewRecorder()
	mgr.SetSessionCookie(login, user)
	sessionCookie := login.Result().Cookies()[0]

	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.AddCookie(sessionCookie)
		return req
	}
	if got, err := mgr.GetSessionUser(request(), nil); err != nil || got.ID != user.ID {
		t.Fatalf("fresh session: user=%v err=%v", got, err)
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.AddCookie(sessionCookie)
	recorder := httptest.NewRecorder()
	LogoutHandler(mgr)(recorder, logout)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d", recorder.Code)
	}
	if _, err := mgr.GetSessionUser(request(), nil); err == nil {
		t.Fatal("a cookie copied before logout must no longer authenticate")
	}

	legacy := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	legacy.AddCookie(&http.Cookie{Name: "hibou_session", Value: "aa|bb|cc"})
	if _, err := mgr.GetSessionUser(legacy, nil); err == nil {
		t.Fatal("a pre-epoch cookie must be rejected")
	}
}
