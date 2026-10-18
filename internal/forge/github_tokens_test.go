package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

// tokenServer is a GitHub App API that records every token request.
type tokenServer struct {
	mu       sync.Mutex
	listings int
	requests []installationTokenRequest
}

func (s *tokenServer) handler(permissions string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/app/installations":
			s.listings++
			_, _ = w.Write([]byte(`[{"id":7,"account":{"id":42,"login":"acme"},"permissions":` + permissions + `}]`))
		case "/app/installations/7/access_tokens":
			var body installationTokenRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.requests = append(s.requests, body)
			_, _ = w.Write([]byte(`{"token":"t-` + body.Repositories0() + `","expires_at":"2099-01-01T00:00:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	})
}

// Repositories0 names a token by its repository in the fake server.
func (r installationTokenRequest) Repositories0() string {
	if len(r.Repositories) == 0 {
		return "account"
	}
	return r.Repositories[0]
}

const reportInstallation = `{"contents":"read","metadata":"read","members":"read","checks":"write","statuses":"write","pull_requests":"write"}`

func newTokenTestGitHub(t *testing.T, permissions string, tier Tier) (*GitHub, *tokenServer) {
	t.Helper()
	fake := &tokenServer{}
	server := httptest.NewServer(fake.handler(permissions))
	t.Cleanup(server.Close)
	return NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(tier)), fake
}

// Every token names the one repository and the permissions its operation
// needs; tokens and the installation listing are reused.
func TestScopedInstallationTokenNarrowsRepositoryAndPermissions(t *testing.T) {
	t.Parallel()

	g, fake := newTokenTestGitHub(t, reportInstallation, TierReport)
	ctx := context.Background()

	token, err := g.CloneToken(ctx, "acme", "app")
	if err != nil || token != "t-app" {
		t.Fatalf("CloneToken = %q, %v", token, err)
	}
	if _, err := g.CloneToken(ctx, "acme", "app"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.scopedInstallationToken(ctx, "acme", TokenScope{Repo: "web", Permissions: map[string]string{"checks": "write"}}); err != nil {
		t.Fatal(err)
	}

	want := []installationTokenRequest{
		{Repositories: []string{"app"}, Permissions: map[string]string{"contents": "read"}},
		{Repositories: []string{"web"}, Permissions: map[string]string{"checks": "write"}},
	}
	if !reflect.DeepEqual(fake.requests, want) {
		t.Fatalf("token requests = %+v, want %+v (the second clone token must come from the cache)", fake.requests, want)
	}
	if fake.listings != 1 {
		t.Fatalf("installations listed %d times, want 1 (cached)", fake.listings)
	}
}

// An operation above the tier is refused before any token is minted, and a
// permission the installation lacks is named instead of failing at GitHub.
func TestScopedInstallationTokenRefusals(t *testing.T) {
	t.Parallel()

	g, fake := newTokenTestGitHub(t, reportInstallation, TierReport)
	ctx := context.Background()
	if _, err := g.scopedInstallationToken(ctx, "acme", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "write"}}); !errors.Is(err, ErrTierForbids) {
		t.Fatalf("contents write on tier report = %v, want ErrTierForbids", err)
	}
	if len(fake.requests) != 0 {
		t.Fatal("a refused operation minted a token")
	}

	unset, _ := newTokenTestGitHub(t, reportInstallation, TierUnset)
	if _, err := unset.scopedInstallationToken(ctx, "acme", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "write"}}); !errors.Is(err, ErrInstallationLacksPermission) {
		t.Fatalf("contents write the installation lacks = %v, want ErrInstallationLacksPermission", err)
	}
}

// An undeclared need gets the tier's cap, trimmed to what the installation
// holds, so GitHub never refuses the token for a missing permission.
func TestResolveTokenPermissionsUndeclared(t *testing.T) {
	t.Parallel()

	installed := map[string]string{"contents": "write", "metadata": "read", "pull_requests": "write"}
	got, err := resolveTokenPermissions(TierReport, installed, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"contents": "read", "metadata": "read", "pull_requests": "write"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("undeclared on report = %v, want %v (contents capped to read, absent permissions dropped)", got, want)
	}
	if got, err := resolveTokenPermissions(TierUnset, installed, nil); err != nil || got != nil {
		t.Fatalf("undeclared on unset tier = %v, %v; want the installation's own permissions (nil)", got, err)
	}
}

func TestScopeForRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		method, path string
		want         TokenScope
	}{
		{http.MethodGet, "/repos/acme/app/contents/.hibou.yaml", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "read"}}},
		{http.MethodPut, "/repos/acme/app/contents/.hibou.yaml", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "write"}}},
		{http.MethodPost, "/repos/acme/app/git/refs", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "write"}}},
		{http.MethodPost, "/repos/acme/app/pulls", TokenScope{Repo: "app", Permissions: map[string]string{"pull_requests": "write"}}},
		{http.MethodPost, "/repos/acme/app/issues/3/comments", TokenScope{Repo: "app", Permissions: map[string]string{"pull_requests": "write"}}},
		{http.MethodPost, "/repos/acme/app/statuses/abc", TokenScope{Repo: "app", Permissions: map[string]string{"statuses": "write"}}},
		{http.MethodGet, "/repos/acme/app/commits/abc/status", TokenScope{Repo: "app", Permissions: map[string]string{"statuses": "read"}}},
		{http.MethodGet, "/repos/acme/app/commits/abc/check-runs", TokenScope{Repo: "app", Permissions: map[string]string{"checks": "read"}}},
		{http.MethodGet, "/repos/acme/app", TokenScope{Repo: "app", Permissions: map[string]string{"metadata": "read"}}},
		{http.MethodGet, "/repos/acme/app/collaborators/x/permission", TokenScope{Repo: "app", Permissions: map[string]string{"metadata": "read"}}},
		{http.MethodGet, "/repos/acme/app/hooks", TokenScope{Repo: "app"}},
		{http.MethodGet, "/orgs/acme/members/x", TokenScope{}},
	}
	for _, tc := range cases {
		request := httptest.NewRequest(tc.method, "https://api.github.com"+tc.path, nil)
		if got := scopeForRequest(request); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %s = %+v, want %+v", tc.method, tc.path, got, tc.want)
		}
	}
}

// A repository call with no declared permissions is refused while the
// tests' strict mode is on, before any token is minted.
func TestUndeclaredScopeFailsInTests(t *testing.T) {
	t.Parallel()

	g, fake := newTokenTestGitHub(t, reportInstallation, TierReport)
	request := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/acme/app/hooks", nil)
	if err := g.authorizeForOwner(context.Background(), request, "acme"); !errors.Is(err, ErrUndeclaredScope) {
		t.Fatalf("undeclared call = %v, want ErrUndeclaredScope", err)
	}
	if len(fake.requests) != 0 {
		t.Fatal("an undeclared call minted a token")
	}
}

func TestParseTier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want Tier
	}{{"", TierUnset}, {"read", TierRead}, {" Report ", TierReport}, {"PROPOSE", TierPropose}}
	for _, tc := range cases {
		if got, err := ParseTier(tc.in); err != nil || got != tc.want {
			t.Errorf("ParseTier(%q) = %q, %v", tc.in, got, err)
		}
	}
	if _, err := ParseTier("admin"); err == nil {
		t.Error("ParseTier(admin) accepted")
	}
}

// A repository outside the installation is refused at token time (422);
// reading a file there is "not found", as the broad token's 404 was.
func TestScopedTokenForRepositoryOutsideInstallation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			_, _ = w.Write([]byte(`[{"id":7,"account":{"id":42,"login":"acme"},"permissions":` + reportInstallation + `}]`))
		case "/app/installations/7/access_tokens":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	g := NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(TierReport))

	if _, err := g.GetFileContent(context.Background(), "acme", "elsewhere", ".hibou.yaml", "main"); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("GetFileContent outside the installation = %v, want ErrFileNotFound", err)
	}
	if _, err := g.CloneToken(context.Background(), "acme", "elsewhere"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("CloneToken outside the installation = %v, want ErrRepositoryNotFound", err)
	}
}
