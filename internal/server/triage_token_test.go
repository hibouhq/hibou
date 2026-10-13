package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

// CVE triage acts with instance authority: no API token reaches it, not even
// an org-wide admin:write token, and not an unscoped legacy token either.
func TestTriageRoutesRefuseEveryAPIToken(t *testing.T) {
	t.Parallel()

	adminOrgWide := apitoken.Scope{
		Org:         "acme",
		Repos:       apitoken.RepoSelector{Mode: apitoken.RepoAll},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapAdmin: apitoken.AccessWrite},
	}
	itemID := uuid.NewString()
	for _, route := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/orgs/github/acme/triage/"},
		{http.MethodGet, "/api/v1/orgs/github/acme/triage/" + itemID},
		{http.MethodPost, "/api/v1/orgs/github/acme/triage/" + itemID + "/decision"},
	} {
		srv := newRoutedTestServer(t)
		reached := false
		recorder := httptest.NewRecorder()
		srv.tokenScopeGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})).ServeHTTP(recorder, scopedTokenRequest(t, route.method, route.target, adminOrgWide))
		if reached || recorder.Code != http.StatusForbidden {
			t.Errorf("%s %s with an admin:write token: reached=%v status=%d, want 403", route.method, route.target, reached, recorder.Code)
		}
	}

	// An unscoped token passes the route guard; the handler refuses it.
	srv := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/github/acme/triage/", nil)
	ctx := auth.WithUser(req.Context(), &store.User{ID: uuid.New()})
	ctx = auth.WithTokenAuth(ctx, &auth.TokenAuth{KeyID: uuid.New()})
	recorder := httptest.NewRecorder()
	if _, ok := srv.loadTriageOrg(recorder, req.WithContext(ctx)); ok || recorder.Code != http.StatusForbidden {
		t.Fatalf("unscoped token: ok=%v status=%d, want 403", ok, recorder.Code)
	}
}
