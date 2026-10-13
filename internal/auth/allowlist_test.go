package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// installedOrgProvider answers membership with the installation token for the
// orgs it is installed on.
type installedOrgProvider struct {
	forge.Provider
	installed []string
	members   map[string]bool
	err       error
	calls     int
}

func (p *installedOrgProvider) Installations(context.Context) ([]forge.Installation, error) {
	out := make([]forge.Installation, 0, len(p.installed))
	for _, account := range p.installed {
		out = append(out, forge.Installation{AccountName: account})
	}
	return out, nil
}

func (p *installedOrgProvider) IsOrgMember(_ context.Context, token *oauth2.Token, login, _ string) (bool, error) {
	p.calls++
	if token != nil {
		return false, errors.New("re-check must not need a user token")
	}
	return p.members[login], p.err
}

// Q5: the allowlist governs every request, not only the OAuth callback.
func TestUserAllowedAppliesAllowlistAfterSignIn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	recent := time.Now().Add(-time.Hour)
	stale := time.Now().Add(-48 * time.Hour)
	old := time.Now().Add(-30 * 24 * time.Hour)
	user := func(login string, allowedAt *time.Time) *store.User {
		return &store.User{ID: uuid.New(), Provider: "github", ProviderID: "583231", ForgeLogin: login, SignInAllowedAt: allowedAt}
	}

	if !New(Config{}, nil).UserAllowed(ctx, user("", nil)) {
		t.Fatal("no allowlist must admit everyone")
	}

	byID := New(Config{AllowedUsers: []string{"GitHub:583231"}}, nil)
	if !byID.UserAllowed(ctx, user("", nil)) {
		t.Error("provider:id entry must match the immutable id")
	}
	byLogin := New(Config{AllowedUsers: []string{"octocat"}}, nil)
	if byLogin.UserAllowed(ctx, user("", nil)) {
		t.Error("a pre-allowlist account with no recorded login must be refused")
	}
	if !byLogin.UserAllowed(ctx, user("Octocat", nil)) {
		t.Error("login entry must match the recorded login")
	}

	provider := &installedOrgProvider{installed: []string{"hibouhq"}, members: map[string]bool{"dev": true}}
	orgs := New(Config{AllowedOrgs: []string{"hibouhq"}, Providers: map[string]forge.Provider{"github": provider}}, nil)
	if !orgs.UserAllowed(ctx, user("someone", &recent)) || provider.calls != 0 {
		t.Errorf("a recent confirmation must stand without a forge call (calls=%d)", provider.calls)
	}
	if !orgs.UserAllowed(ctx, user("dev", &stale)) {
		t.Error("a stale confirmation of a current member must be renewed")
	}
	if orgs.UserAllowed(ctx, user("gone", &stale)) {
		t.Error("someone who left every allowed org must be refused")
	}
	if orgs.UserAllowed(ctx, user("someone", nil)) {
		t.Error("an account never admitted through the org must be refused")
	}

	// The forge cannot answer (not installed): a recent enough sign-in is
	// trusted, an old one is not.
	uninstalled := &installedOrgProvider{}
	blind := New(Config{AllowedOrgs: []string{"hibouhq"}, Providers: map[string]forge.Provider{"github": uninstalled}}, nil)
	if !blind.UserAllowed(ctx, user("dev", &stale)) {
		t.Error("an unanswerable re-check within the grace period must admit")
	}
	if blind.UserAllowed(ctx, user("dev", &old)) {
		t.Error("an unanswerable re-check past the grace period must refuse")
	}
	if uninstalled.calls != 0 {
		t.Error("membership must not be asked without an installation")
	}
}

// Q4: an org-owned key whose creator left the org stops authenticating; a
// deleted creator does not stop it (ADR-022).
func TestValidateAPIKeyRefusesKeysOfDepartedCreators(t *testing.T) {
	t.Parallel()

	orgID := uuid.New()
	key := &store.APIKey{OwnerType: "org", OwnerID: &orgID, User: &store.User{ID: uuid.New()}, CreatorLeftOrg: true}
	if err := ValidateAPIKey(key, time.Now()); !errors.Is(err, ErrTokenCreatorLeftOrg) {
		t.Fatalf("err = %v, want ErrTokenCreatorLeftOrg", err)
	}
	key.CreatorLeftOrg = false
	key.User = nil
	if err := ValidateAPIKey(key, time.Now()); err != nil {
		t.Fatalf("org key with deleted creator: %v", err)
	}
	if err := ValidateAPIKey(&store.APIKey{OwnerType: "user"}, time.Now()); err == nil {
		t.Fatal("user key without a user must fail")
	}
}

// S3: the CSRF exemption keys on either session cookie name.
func TestHasSessionCookie(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"hibou_session", "__Host-hibou_session"} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: name, Value: "x"})
		if !HasSessionCookie(req) {
			t.Errorf("%s not detected", name)
		}
	}
	if HasSessionCookie(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Error("no cookie detected as a session")
	}
}

// S3: revocation runs the hooks (websocket close).
func TestRevokeSessionsRunsHooks(t *testing.T) {
	t.Parallel()

	var mgr *Manager
	mgr.AddRevokeHook(func(uuid.UUID) {}) // nil manager: no panic
	mgr = New(Config{}, nil)
	if err := mgr.RevokeSessions(context.Background(), uuid.New()); err == nil {
		t.Fatal("RevokeSessions without queries must fail before running hooks")
	}
}

// perOrgProvider answers membership per org: a 404 ("not a member") or an
// error (no installation token, a 302, a 5xx).
type perOrgProvider struct {
	forge.Provider
	errs map[string]error
}

func (p *perOrgProvider) Installations(context.Context) ([]forge.Installation, error) {
	return []forge.Installation{{AccountName: "a"}, {AccountName: "b"}}, nil
}

func (p *perOrgProvider) IsOrgMember(_ context.Context, _ *oauth2.Token, _, org string) (bool, error) {
	return false, p.errs[org]
}

// A denial needs a definitive 404 from every allowed org. One org that could
// not answer keeps the grace window open.
func TestUserAllowedKeepsGraceUnlessEveryOrgSaysNo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	stale := time.Now().Add(-48 * time.Hour)
	user := &store.User{ID: uuid.New(), Provider: "github", ProviderID: "1", ForgeLogin: "dev", SignInAllowedAt: &stale}

	partial := New(Config{AllowedOrgs: []string{"a", "b"}, Providers: map[string]forge.Provider{
		"github": &perOrgProvider{errs: map[string]error{"b": errors.New("no installation token for b")}},
	}}, nil)
	if !partial.UserAllowed(ctx, user) {
		t.Error("one unanswerable org must keep the grace window, not deny")
	}

	definitive := New(Config{AllowedOrgs: []string{"a", "b"}, Providers: map[string]forge.Provider{
		"github": &perOrgProvider{},
	}}, nil)
	if definitive.UserAllowed(ctx, user) {
		t.Error("every allowed org answering \"not a member\" must deny")
	}
}
