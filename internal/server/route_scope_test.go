package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/ws"
)

// publicRoutes are served outside auth.SessionAuth, so the scoped-token guard
// never runs for them and they need no capability declaration.
var publicRoutes = map[string]struct{}{
	"GET /api/v1/health":                           {},
	"GET /api/v1/ready":                            {},
	"GET /api/v1/metrics":                          {},
	"GET /api/v1/version":                          {},
	"GET /api/v1/bin/version":                      {},
	"GET /api/v1/bin/{os}/{arch}":                  {},
	"GET /api/v1/schemas/hibou-config.schema.json": {},
	"GET /api/v1/docs/*":                           {},
	"GET /api/v1/ws":                               {},
	"GET /api/v1/instance/banners":                 {},
	"GET /api/v1/auth/providers":                   {},
	"GET /api/v1/auth/login":                       {},
	"GET /api/v1/auth/callback":                    {},
	"POST /api/v1/auth/logout":                     {},
	"POST /api/v1/auth/dev-login":                  {},
	"POST /api/v1/auth/device/code":                {},
	"POST /api/v1/auth/device/token":               {},
	"POST /api/v1/webhooks/{provider}/":            {},
}

func newRoutedTestServer(t *testing.T) *Server {
	t.Helper()

	srv := &Server{
		router: chi.NewRouter(),
		wsHub:  ws.NewHub(zerolog.New(io.Discard)),
		log:    zerolog.New(io.Discard),
	}
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)
	return srv
}

func registeredAPIRoutes(t *testing.T, srv *Server) []string {
	t.Helper()

	var routes []string
	err := chi.Walk(srv.router, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/api/v1/") {
			routes = append(routes, method+" "+route)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	sort.Strings(routes)
	return routes
}

func TestEveryAuthenticatedRouteDeclaresScope(t *testing.T) {
	t.Parallel()

	srv := newRoutedTestServer(t)

	var undeclared []string
	for _, route := range registeredAPIRoutes(t, srv) {
		if _, public := publicRoutes[route]; public {
			continue
		}
		if _, declared := routeScopes[route]; !declared {
			undeclared = append(undeclared, route)
		}
	}
	if len(undeclared) > 0 {
		t.Fatalf("routes reachable with a scoped token but missing a routeScopes declaration:\n  %s", strings.Join(undeclared, "\n  "))
	}
}

func TestRouteScopeDeclarationsMatchRegisteredRoutes(t *testing.T) {
	t.Parallel()

	srv := newRoutedTestServer(t)
	registered := make(map[string]struct{})
	for _, route := range registeredAPIRoutes(t, srv) {
		registered[route] = struct{}{}
	}

	var stale []string
	for route := range routeScopes {
		if _, ok := registered[route]; !ok {
			stale = append(stale, route)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("routeScopes declares routes that are not registered:\n  %s", strings.Join(stale, "\n  "))
	}
}

func scopedTokenRequest(t *testing.T, method, target string, scope apitoken.Scope) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	ctx := auth.WithTokenAuth(req.Context(), &auth.TokenAuth{KeyID: uuid.New(), Scope: scope, Scoped: true})
	return req.WithContext(ctx)
}

func TestTokenScopeGuardDeniesUndeclaredAndUnmatchedRoutes(t *testing.T) {
	t.Parallel()

	srv := newRoutedTestServer(t)
	scope := apitoken.Scope{
		Org:         "acme",
		Repos:       apitoken.RepoSelector{Mode: apitoken.RepoAll},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapCoverage: apitoken.AccessWrite},
	}

	recorder := httptest.NewRecorder()
	srv.tokenScopeGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler reached for an unmatched route")
	})).ServeHTTP(recorder, scopedTokenRequest(t, http.MethodGet, "/api/v1/orgs/github/acme/does-not-exist", scope))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unmatched route status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestTokenScopeGuardEnforcesDeclaredRoutes(t *testing.T) {
	t.Parallel()

	repoScoped := apitoken.Scope{
		Org:   "acme",
		Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"api"}},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{
			apitoken.CapCoverage:   apitoken.AccessRead,
			apitoken.CapUploads:    apitoken.AccessWrite,
			apitoken.CapTriage:     apitoken.AccessRead,
			apitoken.CapAdmin:      apitoken.AccessWrite,
			apitoken.CapSecrets:    apitoken.AccessRead,
			apitoken.CapComponents: apitoken.AccessRead,
		},
	}
	orgWide := apitoken.Scope{
		Org:   "acme",
		Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{
			apitoken.CapVulnerabilities: apitoken.AccessRead,
			apitoken.CapCoverage:        apitoken.AccessRead,
		},
	}
	emptyScope := apitoken.Scope{Org: "acme", Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll}}

	tests := []struct {
		name   string
		method string
		target string
		scope  apitoken.Scope
		allow  bool
	}{
		{"coverage read in allowlist", http.MethodGet, "/api/v1/orgs/github/acme/repos/api/coverage", repoScoped, true},
		{"coverage read outside allowlist", http.MethodGet, "/api/v1/orgs/github/acme/repos/web/coverage", repoScoped, false},
		{"coverage read in another org", http.MethodGet, "/api/v1/orgs/github/other/repos/api/coverage", repoScoped, false},
		{"triage write with read grant", http.MethodPut, "/api/v1/orgs/github/acme/repos/api/vulnerabilities/acceptance", repoScoped, false},
		{"org-wide read from repo-list token", http.MethodGet, "/api/v1/orgs/github/acme/vulnerabilities", repoScoped, false},
		{"org-wide read from org-wide token", http.MethodGet, "/api/v1/orgs/github/acme/vulnerabilities", orgWide, true},
		{"org-wide read in another org", http.MethodGet, "/api/v1/orgs/github/other/vulnerabilities", orgWide, false},
		{"org metadata needs only a grant", http.MethodGet, "/api/v1/orgs/github/acme", repoScoped, true},
		{"org metadata denied to a permissionless token", http.MethodGet, "/api/v1/orgs/github/acme", emptyScope, false},
		{"org metadata with trailing slash", http.MethodGet, "/api/v1/orgs/github/acme/", repoScoped, true},
		{"repo listing denied to repo-list token", http.MethodGet, "/api/v1/orgs/github/acme/repos", repoScoped, false},
		{"repo listing allowed org-wide", http.MethodGet, "/api/v1/orgs/github/acme/repos", orgWide, true},
		{"repo listing with trailing slash", http.MethodGet, "/api/v1/orgs/github/acme/repos/", orgWide, true},
		{"admin write is org-wide only", http.MethodPut, "/api/v1/orgs/github/acme/settings", repoScoped, false},
		{"api key mint is session only", http.MethodPost, "/api/v1/users/me/api-keys", repoScoped, false},
		{"cli token mint is session only", http.MethodPost, "/api/v1/auth/cli-token", orgWide, false},
		{"notifications are session only", http.MethodGet, "/api/v1/notifications", orgWide, false},
		{"identity is always readable", http.MethodGet, "/api/v1/users/me", emptyScope, true},
		{"upload write", http.MethodPost, "/api/v1/upload", repoScoped, true},
		{"upload write denied without grant", http.MethodPost, "/api/v1/upload", orgWide, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newRoutedTestServer(t)
			reached := false
			recorder := httptest.NewRecorder()
			srv.tokenScopeGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(recorder, scopedTokenRequest(t, tc.method, tc.target, tc.scope))

			if reached != tc.allow {
				t.Fatalf("handler reached = %v, want %v (status %d, body %s)", reached, tc.allow, recorder.Code, recorder.Body.String())
			}
			if !tc.allow && recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
			}
		})
	}
}

func TestTokenScopeGuardIgnoresSessionsAndUnscopedTokens(t *testing.T) {
	t.Parallel()

	srv := newRoutedTestServer(t)

	for _, tc := range []struct {
		name    string
		request *http.Request
	}{
		{"session", httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/github/acme", nil)},
		{"unscoped token", func() *http.Request {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/orgs/github/acme", nil)
			return req.WithContext(auth.WithTokenAuth(req.Context(), &auth.TokenAuth{KeyID: uuid.New()}))
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			recorder := httptest.NewRecorder()
			srv.tokenScopeGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(recorder, tc.request)

			if !reached {
				t.Fatalf("handler not reached (status %d)", recorder.Code)
			}
		})
	}
}

// The IDE extensions read their owner's search presets with the IDE token;
// creating, changing and deleting presets stays a browser action (ADR-042,
// amending ADR-033).
func TestSearchPresetsReadableByTokenWritesSessionOnly(t *testing.T) {
	t.Parallel()

	readOnly := apitoken.Scope{Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapVulnerabilities: apitoken.AccessRead}}
	if rs, ok := routeScopes["GET /api/v1/users/me/search-presets/"]; !ok || !rs.allows(readOnly, "", "") {
		t.Fatal("a token must be able to read its owner's search presets")
	}
	for _, route := range []string{
		"POST /api/v1/users/me/search-presets/",
		"PUT /api/v1/users/me/search-presets/{presetID}",
		"DELETE /api/v1/users/me/search-presets/{presetID}",
	} {
		if rs, ok := routeScopes[route]; !ok || rs.allows(readOnly, "", "") {
			t.Errorf("%s must stay session-only", route)
		}
	}
}
