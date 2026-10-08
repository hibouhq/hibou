package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
)

func TestHandleListOrgComponentsOrgWideTokenScope(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	call := func(tokenAuth *internalauth.TokenAuth) *httptest.ResponseRecorder {
		req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/components", "github", org.Slug)
		if tokenAuth != nil {
			req = req.WithContext(internalauth.WithTokenAuth(req.Context(), tokenAuth))
		}
		recorder := httptest.NewRecorder()
		srv.handleListOrgComponents(recorder, req)
		return recorder
	}

	listScoped := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"allowed-repo"}},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapComponents: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(listScoped); recorder.Code != http.StatusForbidden {
		t.Fatalf("repo-list scoped components = %d: %s", recorder.Code, recorder.Body.String())
	}

	allScoped := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapComponents: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(allScoped); recorder.Code != http.StatusOK {
		t.Fatalf("org-wide scoped components = %d: %s", recorder.Code, recorder.Body.String())
	}

	if recorder := call(&internalauth.TokenAuth{}); recorder.Code != http.StatusOK {
		t.Fatalf("unscoped components = %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(nil); recorder.Code != http.StatusOK {
		t.Fatalf("session components = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleListOrgVulnerabilitiesRejectsInvalidQuery(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	for _, query := range []string{"q=(type:dependency", "q=unknown:value"} {
		recorder := httptest.NewRecorder()
		req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/vulnerabilities?"+query, "github", org.Slug)
		srv.handleListOrgVulnerabilities(recorder, req)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q = %d: %s", query, recorder.Code, recorder.Body.String())
		}
	}
}
