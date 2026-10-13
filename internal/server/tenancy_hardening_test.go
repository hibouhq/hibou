package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/orgprovision"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

// S3: a bearer header is exempt from the CSRF checks only without a session
// cookie, because SessionAuth authenticates the cookie first.
func TestCSRFBearerExemptionNeedsNoSessionCookie(t *testing.T) {
	t.Parallel()

	const base = "https://hibou.example.com"
	for _, cookie := range []string{"hibou_session", "__Host-hibou_session"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", nil)
		req.Header.Set("Authorization", "Bearer hb_anything")
		req.Header.Set("Origin", "https://evil.example.net")
		req.AddCookie(&http.Cookie{Name: cookie, Value: "v"})
		if csrfRequestAllowed(req, base, false) {
			t.Errorf("cross-site bearer request riding a %s cookie was allowed", cookie)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", nil)
	req.Header.Set("Authorization", "Bearer hb_anything")
	req.Header.Set("Origin", "https://evil.example.net")
	if !csrfRequestAllowed(req, base, false) {
		t.Error("cookie-less bearer request must stay exempt")
	}
}

// Config.AllowedOrigins extends the Origin check, never the Sec-Fetch-Site one.
func TestCSRFAllowedOrigins(t *testing.T) {
	t.Parallel()

	const base = "https://hibou.example.com"
	allowed := []string{"https://ide.example.com"}
	request := func(origin, site string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", nil)
		req.Header.Set("Origin", origin)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		return req
	}
	if !csrfRequestAllowed(request("https://IDE.example.com", ""), base, false, allowed...) {
		t.Error("listed origin refused")
	}
	if csrfRequestAllowed(request("https://ide.example.com", "cross-site"), base, false, allowed...) {
		t.Error("listed origin bypassed the Sec-Fetch-Site refusal")
	}
	if csrfRequestAllowed(request("https://other.example.com", ""), base, false, allowed...) {
		t.Error("unlisted origin allowed")
	}
	if csrfRequestAllowed(request("https://ide.example.com", ""), base, false) {
		t.Error("origin allowed without being listed")
	}
}

// P3: an opaque provider id that is not in the org's inventory has no owner
// to check, so enrolment is refused rather than skipping the owner check.
func TestHandleEnrollRepoRefusesUnresolvableOwner(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	recorder := httptest.NewRecorder()
	srv.handleEnrollRepo(recorder, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{
		"name":        "victim",
		"slug":        "victim",
		"provider_id": "987654321",
	}))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("enroll opaque unknown id = %d, want 422: %s", recorder.Code, recorder.Body)
	}
}

// P3: a repository name is a forge-coordinate fallback, so it may not look
// like coordinates — on enrolment or on update.
func TestRepoNameCannotCarryCoordinates(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	for _, name := range []string{"victim/repo", "..", "a\\b"} {
		recorder := httptest.NewRecorder()
		srv.handleEnrollRepo(recorder, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{
			"name":        name,
			"slug":        "named",
			"provider_id": org.Slug + "/named",
		}))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("enroll name %q = %d, want 400", name, recorder.Code)
		}
	}

	repo, err := srv.queries.CreateRepository(context.Background(), org.ID, nil, "named", "named", org.Provider, org.Slug+"/named", "main", "enrolled")
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"name": "victim/repo"})
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", org.Provider)
	rctx.URLParams.Add("slug", org.Slug)
	rctx.URLParams.Add("repoSlug", repo.Slug)
	req = req.WithContext(context.WithValue(internalauth.WithUser(req.Context(), admin), chi.RouteCtxKey, rctx))
	recorder := httptest.NewRecorder()
	srv.handleUpdateRepo(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("rename to coordinates = %d, want 400: %s", recorder.Code, recorder.Body)
	}
}

// P3: the gate config of a compare/PR is read only through owner-bound
// coordinates of the snapshot's own repository — a name or provider id
// naming another account reaches no forge.
func TestResolveRepoGateConfigRefusesForeignCoordinates(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	foreign := uniqueName(t, "victim")
	repo, err := srv.queries.CreateRepository(ctx, org.ID, nil, "legacy", "legacy", org.Provider, foreign+"/secret", "main", "enrolled")
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}
	ref, err := srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{})
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	snapshot, err := srv.queries.UpsertSnapshotForBuild(ctx, ref.ID, "abc", store.SnapshotStatusComplete, store.SnapshotBuildMeta{})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	fake := &scannerScopeForge{
		compareCountingForge: &compareCountingForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}},
		config:               "version: 1\ngates:\n  - branches: [main]\n    secrets:\n      max_new: 0\n",
	}
	srv.forges = map[string]forge.Provider{"github": fake}
	srv.repoConfigLoader = repoconfig.NewLoader(srv.forges, srv.log)
	bindTestOrgToForgeAccount(t, srv, org, "acme")

	// The coordinate arguments name this org's account; the repository row
	// names another one. The row decides.
	if got := srv.resolveRepoGateConfig(ctx, repo.Provider, repo.DefaultBranch, "acme/app", "app", "app", snapshot.ID); got != nil {
		t.Fatalf("gate config = %+v, want nil", got)
	}
	if n := fake.reads.Load(); n != 0 {
		t.Fatalf("forge was read %d times for a foreign owner", n)
	}
	if _, err := srv.db.Exec(`UPDATE repositories SET provider_id = 'acme/app' WHERE id = $1`, repo.ID); err != nil {
		t.Fatal(err)
	}
	srv.resolveRepoGateConfig(ctx, repo.Provider, repo.DefaultBranch, "", "", "", snapshot.ID)
	if n := fake.reads.Load(); n == 0 {
		t.Fatal("bound repository config was never read")
	}
}

// Q4: a repository-scoped member whose grants are gone (their only granted
// repository was deleted) sees nothing — never the whole org.
func TestRepoScopedMemberWithoutGrantsFailsClosed(t *testing.T) {
	f := newAuthzFixture(t, "only", "other")
	collaborator := f.forgeUser(t, "viewer", map[string]string{"only": "viewer"})
	if err := f.srv.queries.DeleteRepository(context.Background(), f.repo["only"].ID); err != nil {
		t.Fatalf("delete repo: %v", err)
	}
	if got := f.repoStatus(collaborator, http.MethodGet, "other"); got != http.StatusNotFound {
		t.Errorf("scoped member without grants on other repo = %d, want 404", got)
	}
	if got := f.orgStatus(collaborator, http.MethodGet); got != http.StatusForbidden {
		t.Errorf("scoped member without grants on org view = %d, want 403", got)
	}
	f.addRepo(t, "later")
	if got := f.repoStatus(collaborator, http.MethodGet, "later"); got != http.StatusNotFound {
		t.Errorf("scoped member on a repo enrolled later = %d, want 404", got)
	}
	ids, err := f.srv.queries.ListRepoAudienceUserIDs(context.Background(), f.repo["later"].ID)
	if err != nil {
		t.Fatalf("audience: %v", err)
	}
	for _, id := range ids {
		if id == collaborator.ID {
			t.Error("scoped member without a grant is in the live audience")
		}
	}
}

// S3: a manually created GitHub org is bound to the installed account it was
// authorized against.
func TestBindCreatedOrgRecordsForgeAccount(t *testing.T) {
	t.Parallel()

	srv, _, _, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	org, err := srv.queries.CreateOrganization(ctx, uniqueName(t, "bind"), uniqueName(t, "bind"), "Bind", "github")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	tx, err := srv.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	accountID := uuid.NewString()
	recorder := httptest.NewRecorder()
	if !srv.bindCreatedOrg(recorder, httptest.NewRequest(http.MethodPost, "/", nil), tx, org, orgprovision.ForgeAccount{Login: "Acme-Login", ID: accountID}) {
		t.Fatalf("bind refused: %d %s", recorder.Code, recorder.Body)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	stored, err := srv.queries.GetOrganizationByID(ctx, org.ID)
	if err != nil || stored == nil {
		t.Fatalf("reload org: %v", err)
	}
	if stored.ForgeAccountLogin != "Acme-Login" || stored.ForgeAccountID != accountID {
		t.Fatalf("binding = %q/%q", stored.ForgeAccountLogin, stored.ForgeAccountID)
	}
}
