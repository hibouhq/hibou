package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
)

func TestHandleGlobalSearchOrgWideTokenScope(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	call := func(tokenAuth *internalauth.TokenAuth) *httptest.ResponseRecorder {
		req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/search?q=test", "github", org.Slug)
		if tokenAuth != nil {
			req = req.WithContext(internalauth.WithTokenAuth(req.Context(), tokenAuth))
		}
		recorder := httptest.NewRecorder()
		srv.handleGlobalSearch(recorder, req)
		return recorder
	}

	listScoped := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"allowed-repo"}},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapVulnerabilities: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(listScoped); recorder.Code != http.StatusForbidden {
		t.Fatalf("repo-list scoped search = %d: %s", recorder.Code, recorder.Body.String())
	}

	allScoped := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapVulnerabilities: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(allScoped); recorder.Code != http.StatusOK {
		t.Fatalf("org-wide scoped search = %d: %s", recorder.Code, recorder.Body.String())
	}

	if recorder := call(&internalauth.TokenAuth{}); recorder.Code != http.StatusOK {
		t.Fatalf("unscoped search = %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(nil); recorder.Code != http.StatusOK {
		t.Fatalf("session search = %d: %s", recorder.Code, recorder.Body.String())
	}
}
