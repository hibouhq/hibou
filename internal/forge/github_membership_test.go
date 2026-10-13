package forge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// fakeAppAPI serves an App installed on Acme (account 42, installation 7) and
// on a personal account (43, installation 8). Members of Acme: "member";
// "public" answers with GitHub's 302 to the public-members list.
func fakeAppAPI(t *testing.T, mintStatus int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var mints atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			_, _ = w.Write([]byte(`[{"id":7,"account":{"id":42,"login":"Acme","type":"Organization"}},` +
				`{"id":8,"account":{"id":43,"login":"solo","type":"User"}}]`))
			return
		case "/app/installations/7/access_tokens", "/app/installations/8/access_tokens":
			mints.Add(1)
			if mintStatus != http.StatusCreated {
				w.WriteHeader(mintStatus)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"inst-token","expires_at":"2099-01-01T00:00:00Z"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer inst-token" {
			// What an anonymous request sees: nobody is a member.
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/orgs/Acme/members/member":
			w.WriteHeader(http.StatusNoContent)
		case "/orgs/Acme/members/public":
			http.Redirect(w, r, "/orgs/Acme/public_members/public", http.StatusFound)
		case "/orgs/Acme/public_members/public":
			http.NotFound(w, r)
		case "/orgs/Acme/members/broken":
			w.WriteHeader(http.StatusInternalServerError)
		case "/user/1001":
			_, _ = w.Write([]byte(`{"id":1001,"login":"boss"}`))
		case "/user/1002":
			_, _ = w.Write([]byte(`{"id":1002,"login":"dev"}`))
		case "/user/2001":
			_, _ = w.Write([]byte(`{"id":2001,"login":"member"}`))
		case "/user/2002":
			_, _ = w.Write([]byte(`{"id":2002,"login":"gone"}`))
		case "/user/2003":
			_, _ = w.Write([]byte(`{"id":2003,"login":"public"}`))
		case "/user/2005":
			// A lying or confused API: asked about 2005, answers 2001.
			_, _ = w.Write([]byte(`{"id":2001,"login":"member"}`))
		case "/repos/Acme/api/collaborators/member/permission":
			_, _ = w.Write([]byte(`{"permission":"write","role_name":"write","user":{"id":2001}}`))
		case "/repos/Acme/api/collaborators/gone/permission":
			_, _ = w.Write([]byte(`{"permission":"none","role_name":"","user":{"id":2002}}`))
		case "/orgs/Acme/memberships/boss":
			_, _ = w.Write([]byte(`{"state":"active","role":"admin","user":{"id":1001}}`))
		case "/orgs/Acme/memberships/dev":
			_, _ = w.Write([]byte(`{"state":"active","role":"member","user":{"id":1002}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &mints
}

func appGitHub(t *testing.T, server *httptest.Server) *GitHub {
	t.Helper()
	return NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithHTTPClient(server.Client()), WithAppCredentials(1, testAppKeyPEM(t)))
}

// Only a 404 to an authenticated request means "not a member". A missing
// installation token and GitHub's 302 (the requester cannot see the member
// list) are errors, never a silent anonymous "no".
func TestGitHubIsOrgMemberNeverAnswersNoWithoutAToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	server, _ := fakeAppAPI(t, http.StatusCreated)
	g := appGitHub(t, server)
	if member, err := g.IsOrgMember(ctx, nil, "member", "Acme"); err != nil || !member {
		t.Fatalf("member = %v, %v; want true", member, err)
	}
	if member, err := g.IsOrgMember(ctx, nil, "gone", "Acme"); err != nil || member {
		t.Fatalf("404 = %v, %v; want definitive false", member, err)
	}
	if _, err := g.IsOrgMember(ctx, nil, "public", "Acme"); err == nil {
		t.Fatal("302 must be an error, not \"not a member\"")
	}
	if _, err := g.IsOrgMember(ctx, nil, "broken", "Acme"); err == nil {
		t.Fatal("500 must be an error")
	}
	if _, err := g.IsOrgMember(ctx, nil, "member", "NotInstalled"); err == nil {
		t.Fatal("no installation and no user token must be an error, not an anonymous request")
	}

	failing, _ := fakeAppAPI(t, http.StatusForbidden)
	if _, err := appGitHub(t, failing).IsOrgMember(ctx, nil, "member", "Acme"); err == nil {
		t.Fatal("a token that cannot be minted must be an error")
	}
}

// Repository reads in App mode no longer fall back to anonymous requests.
func TestGitHubOwnerRequestsFailWithoutInstallationToken(t *testing.T) {
	t.Parallel()

	server, _ := fakeAppAPI(t, http.StatusForbidden)
	if _, err := appGitHub(t, server).GetFileContent(context.Background(), "Acme", "repo", "README.md", "main"); err == nil {
		t.Fatal("GetFileContent ran without an installation token")
	}
}

// Verifiers are keyed by immutable account id and answer with one token.
func TestGitHubOrgMembershipVerifiers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	server, mints := fakeAppAPI(t, http.StatusCreated)
	verifiers, err := appGitHub(t, server).OrgMembershipVerifiers(ctx)
	if err != nil {
		t.Fatalf("OrgMembershipVerifiers: %v", err)
	}
	acme := verifiers["42"]
	if acme == nil || acme.AccountLogin() != "Acme" {
		t.Fatalf("verifiers = %v, want account 42 (Acme)", verifiers)
	}
	if member, err := acme.IsMember(ctx, "2001"); err != nil || !member {
		t.Fatalf("member = %v, %v", member, err)
	}
	if member, err := acme.IsMember(ctx, "2002"); err != nil || member {
		t.Fatalf("gone = %v, %v", member, err)
	}
	if _, err := acme.IsMember(ctx, "2003"); err == nil {
		t.Fatal("302 must be an error")
	}
	// An id the forge cannot resolve, or resolves to someone else, is an
	// error — never "not a member".
	for _, id := range []string{"2004", "2005", "member"} {
		if _, err := acme.IsMember(ctx, id); err == nil {
			t.Fatalf("IsMember(%q) answered without resolving the id", id)
		}
	}
	if level, err := acme.RepoLevel(ctx, "api", "2001"); err != nil || level != "push" {
		t.Fatalf("RepoLevel(member) = %q, %v; want push", level, err)
	}
	if level, err := acme.RepoLevel(ctx, "api", "2002"); err != nil || level != "" {
		t.Fatalf("RepoLevel(gone) = %q, %v; want none", level, err)
	}
	if got := mints.Load(); got != 1 {
		t.Fatalf("minted %d tokens, want one per verifier", got)
	}
	if _, err := verifiers["43"].IsMember(ctx, "43"); !errors.Is(err, ErrMembershipUnsupported) {
		t.Fatalf("personal account error = %v, want ErrMembershipUnsupported", err)
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(broken.Close)
	if _, err := appGitHub(t, broken).OrgMembershipVerifiers(ctx); err == nil {
		t.Fatal("an installation listing error must be returned, not read as \"installed nowhere\"")
	}
}

// errAny marks a case expecting some error.
var errAny = errors.New("any error")

func TestGitHubIsAccountAdmin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	server, _ := fakeAppAPI(t, http.StatusCreated)
	g := appGitHub(t, server)
	cases := []struct {
		account, user string
		want          bool
		wantErr       error
	}{
		{"42", "1001", true, nil},
		{"42", "1002", false, nil},
		{"42", "9999", false, errAny},
		{"43", "43", true, nil},
		{"43", "1001", false, nil},
		{"77", "1001", false, ErrNoInstallation},
	}
	for _, tc := range cases {
		got, err := g.IsAccountAdmin(ctx, tc.account, tc.user)
		if errors.Is(tc.wantErr, errAny) {
			if err == nil || got {
				t.Errorf("IsAccountAdmin(%s, %s) = %v, %v; want an error", tc.account, tc.user, got, err)
			}
			continue
		}
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("IsAccountAdmin(%s, %s) error = %v, want %v", tc.account, tc.user, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("IsAccountAdmin(%s, %s) = %v, %v; want %v", tc.account, tc.user, got, err, tc.want)
		}
	}
}
