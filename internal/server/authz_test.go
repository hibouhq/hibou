package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ws"
)

func TestRequestChangesState(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		pattern string
		want    bool
	}{
		{"get", http.MethodGet, "/api/v1/orgs/{provider}/{slug}/repos/{repoSlug}/findings", false},
		{"head", http.MethodHead, "", false},
		{"post", http.MethodPost, "/api/v1/orgs/{provider}/{slug}/repos/{repoSlug}/findings", true},
		{"put", http.MethodPut, "", true},
		{"delete", http.MethodDelete, "", true},
		{"sbom compare is a read", http.MethodPost, "/api/v1/orgs/{provider}/{slug}/repos/{repoSlug}/sbom/compare", false},
		{"license simulate is a read", http.MethodPost, "/api/v1/orgs/{provider}/{slug}/licenses/simulate", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, "/", nil)
			rctx := chi.NewRouteContext()
			if tc.pattern != "" {
				rctx.RoutePatterns = []string{tc.pattern}
			}
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
			if got := requestChangesState(request); got != tc.want {
				t.Fatalf("requestChangesState = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRoleCanWrite(t *testing.T) {
	for role, want := range map[string]bool{
		"admin": true, "developer": true, "release_manager": true,
		"viewer": false, "auditor": false, "": false,
	} {
		if got := roleCanWrite(role); got != want {
			t.Errorf("roleCanWrite(%q) = %v, want %v", role, got, want)
		}
	}
}

// A collaborator synced as an org developer (push on some repository) only
// writes where the forge gave them push.
func TestRepoAccessLowersRoleToRepositoryGrant(t *testing.T) {
	pushed, read, other := uuid.New(), uuid.New(), uuid.New()
	access := repoAccess{scoped: true, repos: map[uuid.UUID]string{pushed: "developer", read: "viewer"}}

	if got := access.repoRole("developer", pushed); got != "developer" {
		t.Errorf("role on pushed repo = %q, want developer", got)
	}
	if got := access.repoRole("developer", read); got != "viewer" {
		t.Errorf("role on read-only repo = %q, want viewer", got)
	}
	if access.allows(other) {
		t.Error("ungranted repository allowed")
	}
	if got := (repoAccess{}).repoRole("viewer", other); got != "viewer" {
		t.Errorf("unscoped role = %q, want the org role", got)
	}

	entries := []repositoryInventoryEntry{{ID: &pushed, Slug: "a"}, {ID: &other, Slug: "b"}, {Slug: "not-enrolled"}}
	visible := access.visibleInventory(entries)
	if len(visible) != 1 || visible[0].Slug != "a" {
		t.Fatalf("visible inventory = %+v, want only the granted repo", visible)
	}
	if got := (repoAccess{}).visibleInventory(entries); len(got) != len(entries) {
		t.Fatalf("unscoped inventory filtered: %d of %d", len(got), len(entries))
	}
}

// §4.2: the advisory and watch reads are instance-wide data and SessionAuth
// lets anonymous requests through, so each handler must refuse them.
func TestAdvisoryReadsRequireAuthentication(t *testing.T) {
	srv := &Server{log: zerolog.Nop()}
	handlers := map[string]http.HandlerFunc{
		"advisories":       srv.handleListAdvisories,
		"events":           srv.handleAdvisoryEvents,
		"timeline":         srv.handleAdvisoryTimeline,
		"watches":          srv.handleListWatches,
		"watch candidates": srv.handleListWatchCandidates,
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/instance/advisories/?product=tomcat", nil))
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous status = %d, want 401", recorder.Code)
			}
		})
	}
}

// The cross-org component aggregate is for whoever decides what the instance
// watches; an instance admin passes without a database round-trip.
func TestWatchCandidatesRequireInstanceAuthority(t *testing.T) {
	db := openAuthzTestDB(t)
	srv := &Server{db: db, queries: store.NewQueries(db), log: zerolog.Nop()}
	srv.cfg.InstanceAdmins = []string{"github:4242"}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/instance/advisories/watches/candidates", nil)
	request = request.WithContext(internalauth.WithUser(request.Context(),
		&store.User{ID: uuid.New(), Provider: "github", ProviderID: "4242"}))
	recorder := httptest.NewRecorder()
	srv.handleListWatchCandidates(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("instance admin status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
}

func TestNotificationRuleDestinationRedactedForNonAdmins(t *testing.T) {
	rule := store.NotificationRule{DestinationConfig: json.RawMessage(`{"url":"https://hooks.slack.com/services/T/B/secret"}`)}
	if got := string(redactNotificationRule(rule, false).DestinationConfig); got != "{}" {
		t.Fatalf("non-admin destination = %s, want {}", got)
	}
	if got := string(redactNotificationRule(rule, true).DestinationConfig); got == "{}" {
		t.Fatal("admin destination was redacted")
	}
}

type recordingLive struct {
	users     []uuid.UUID
	broadcast int
}

func (l *recordingLive) PublishToUsers(_ context.Context, userIDs []uuid.UUID, _ ws.Message) {
	l.users = append(l.users, userIDs...)
}

func (l *recordingLive) PublishBroadcast(context.Context, ws.Message) { l.broadcast++ }

type fakeGateAudience struct {
	org   *store.Organization
	repo  *store.Repository
	users []uuid.UUID
}

func (f fakeGateAudience) GetOrganizationByProviderAndSlug(_ context.Context, provider, slug string) (*store.Organization, error) {
	if f.org == nil || f.org.Provider != provider || f.org.Slug != slug {
		return nil, nil
	}
	return f.org, nil
}

func (f fakeGateAudience) GetRepositoryBySlug(_ context.Context, orgID uuid.UUID, slug string) (*store.Repository, error) {
	if f.repo == nil || f.repo.OrgID != orgID || f.repo.Slug != slug {
		return nil, nil
	}
	return f.repo, nil
}

func (f fakeGateAudience) ListRepoAudienceUserIDs(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	return f.users, nil
}

// §4.5: a PR-gate refresh names a private repository and its verdict, so it
// goes to the repository's audience, never to every connected browser.
func TestGateUpdatesGoOnlyToTheRepositoryAudience(t *testing.T) {
	org := &store.Organization{ID: uuid.New(), Provider: "github", Slug: "acme"}
	repo := &store.Repository{ID: uuid.New(), OrgID: org.ID, Slug: "private"}
	member := uuid.New()
	payload := []byte(`{"provider":"github","org_slug":"acme","repo_slug":"private","pr_number":7}`)

	live := &recordingLive{}
	wsGateNotifier{live: live, audience: fakeGateAudience{org: org, repo: repo, users: []uuid.UUID{member}}}.
		PublishGateUpdate(context.Background(), "gate.updated", payload)
	if live.broadcast != 0 {
		t.Fatal("gate update was broadcast")
	}
	if len(live.users) != 1 || live.users[0] != member {
		t.Fatalf("recipients = %v, want only %v", live.users, member)
	}

	// Unknown repository, or no audience resolver: nothing is sent.
	live = &recordingLive{}
	wsGateNotifier{live: live, audience: fakeGateAudience{org: org}}.
		PublishGateUpdate(context.Background(), "gate.updated", payload)
	wsGateNotifier{live: live}.PublishGateUpdate(context.Background(), "gate.updated", payload)
	if live.broadcast != 0 || len(live.users) != 0 {
		t.Fatalf("sent without a resolved audience: users=%v broadcast=%d", live.users, live.broadcast)
	}
}

// --- database-backed: repository-scoped collaborators and read-only roles ---

func openAuthzTestDB(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

type authzFixture struct {
	srv  *Server
	org  *store.Organization
	repo map[string]*store.Repository
}

func newAuthzFixture(t *testing.T, repoSlugs ...string) *authzFixture {
	t.Helper()
	db := openAuthzTestDB(t)
	queries := store.NewQueries(db)
	ctx := context.Background()
	org, err := queries.CreateOrganization(ctx, uniqueName(t, "authz"), uniqueName(t, "authz"), "Authz", "github")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	fixture := &authzFixture{
		srv:  &Server{db: db, queries: queries, log: zerolog.New(io.Discard)},
		org:  org,
		repo: map[string]*store.Repository{},
	}
	for _, slug := range repoSlugs {
		fixture.addRepo(t, slug)
	}
	return fixture
}

func (f *authzFixture) addRepo(t *testing.T, slug string) *store.Repository {
	t.Helper()
	repo, err := f.srv.queries.CreateRepository(context.Background(), f.org.ID, nil, slug, slug, "github", f.org.Slug+"/"+slug, "main", "enrolled")
	if err != nil {
		t.Fatalf("create repo %s: %v", slug, err)
	}
	f.repo[slug] = repo
	return repo
}

// forgeUser creates a user as the permission sync would: a forge-sourced org
// role plus per-repository grants, repository-scoped when the grants miss a
// repository enrolled at that time.
func (f *authzFixture) forgeUser(t *testing.T, orgRole string, grants map[string]string) *store.User {
	t.Helper()
	ctx := context.Background()
	user, err := f.srv.queries.CreateUser(ctx, uniqueName(t, "u")+"@example.com", "U", "github", uniqueName(t, "u"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	for slug, role := range grants {
		if err := f.srv.queries.UpsertForgeUserRepoAccess(ctx, user.ID, f.repo[slug].ID, role); err != nil {
			t.Fatalf("grant %s: %v", slug, err)
		}
	}
	scoped := false
	for slug := range f.repo {
		if _, granted := grants[slug]; !granted {
			scoped = true
		}
	}
	f.syncMembership(t, user, orgRole, scoped)
	return user
}

func (f *authzFixture) syncMembership(t *testing.T, user *store.User, orgRole string, scoped bool) {
	t.Helper()
	if err := f.srv.queries.UpsertForgeOrgMemberScoped(context.Background(), f.org.ID, user.ID, orgRole, scoped); err != nil {
		t.Fatalf("org member: %v", err)
	}
}

func (f *authzFixture) invitedUser(t *testing.T, role string) *store.User {
	t.Helper()
	ctx := context.Background()
	user, err := f.srv.queries.CreateUser(ctx, uniqueName(t, "i")+"@example.com", "I", "github", uniqueName(t, "i"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := f.srv.queries.AddOrgMember(ctx, f.org.ID, user.ID, role); err != nil {
		t.Fatalf("add member: %v", err)
	}
	return user
}

func (f *authzFixture) request(user *store.User, method, repoSlug string) *http.Request {
	request := httptest.NewRequest(method, "/", nil)
	ctx := request.Context()
	if user != nil {
		ctx = internalauth.WithUser(ctx, user)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", f.org.Provider)
	rctx.URLParams.Add("slug", f.org.Slug)
	if repoSlug != "" {
		rctx.URLParams.Add("repoSlug", repoSlug)
	}
	return request.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
}

func (f *authzFixture) repoStatus(user *store.User, method, repoSlug string) int {
	recorder := httptest.NewRecorder()
	if _, _, ok := f.srv.loadAuthorizedRepo(f.request(user, method, repoSlug), recorder); ok {
		return http.StatusOK
	}
	return recorder.Code
}

func (f *authzFixture) repoWithUserStatus(user *store.User, method, repoSlug string) int {
	recorder := httptest.NewRecorder()
	if _, _, _, ok := f.srv.loadAuthorizedRepoWithUser(recorder, f.request(user, method, repoSlug), false); ok {
		return http.StatusOK
	}
	return recorder.Code
}

func (f *authzFixture) orgStatus(user *store.User, method string) int {
	recorder := httptest.NewRecorder()
	if _, ok := f.srv.loadAuthorizedOrg(f.request(user, method, ""), recorder); ok {
		return http.StatusOK
	}
	return recorder.Code
}

// §4.3: a collaborator on one repository sees that repository and nothing
// else of the org, while forge members whose sync covered the whole org and
// invited members are unaffected.
func TestRepoScopedCollaboratorSeesOnlyGrantedRepositories(t *testing.T) {
	f := newAuthzFixture(t, "granted", "secret")
	collaborator := f.forgeUser(t, "viewer", map[string]string{"granted": "viewer"})
	member := f.forgeUser(t, "viewer", map[string]string{"granted": "viewer", "secret": "viewer"})
	invited := f.invitedUser(t, "viewer")

	if got := f.repoStatus(collaborator, http.MethodGet, "granted"); got != http.StatusOK {
		t.Errorf("collaborator on granted repo = %d, want 200", got)
	}
	if got := f.repoStatus(collaborator, http.MethodGet, "secret"); got != http.StatusNotFound {
		t.Errorf("collaborator on ungranted repo = %d, want 404", got)
	}
	if got := f.repoWithUserStatus(collaborator, http.MethodGet, "secret"); got != http.StatusNotFound {
		t.Errorf("collaborator via loadAuthorizedRepoWithUser = %d, want 404", got)
	}
	if got := f.orgStatus(collaborator, http.MethodGet); got != http.StatusForbidden {
		t.Errorf("collaborator on org-wide view = %d, want 403", got)
	}

	// A repository enrolled after the forge member's last sync is not visible
	// through that snapshot: until the forge grants it (the permission sync
	// asks), the member sees only their granted repositories. Invited members
	// are org-wide by definition.
	f.addRepo(t, "newer")
	for _, slug := range []string{"granted", "secret", "newer"} {
		if got := f.repoStatus(invited, http.MethodGet, slug); got != http.StatusOK {
			t.Errorf("invited member on %s = %d, want 200", slug, got)
		}
	}
	if got := f.orgStatus(invited, http.MethodGet); got != http.StatusOK {
		t.Errorf("invited member on org-wide view = %d, want 200", got)
	}
	for _, slug := range []string{"granted", "secret"} {
		if got := f.repoStatus(member, http.MethodGet, slug); got != http.StatusOK {
			t.Errorf("forge member on %s = %d, want 200", slug, got)
		}
	}
	if got := f.repoStatus(member, http.MethodGet, "newer"); got != http.StatusNotFound {
		t.Errorf("forge member on a repo enrolled after sync = %d, want 404 until the forge grants it", got)
	}
	if got := f.orgStatus(member, http.MethodGet); got != http.StatusForbidden {
		t.Errorf("forge member on org-wide view with an unsettled repo = %d, want 403", got)
	}
	if err := f.srv.queries.UpsertForgeUserRepoAccess(context.Background(), member.ID, f.repo["newer"].ID, "viewer"); err != nil {
		t.Fatalf("grant newer: %v", err)
	}
	if got := f.repoStatus(member, http.MethodGet, "newer"); got != http.StatusOK {
		t.Errorf("forge member on newer after the grant = %d, want 200", got)
	}
	if got := f.orgStatus(member, http.MethodGet); got != http.StatusOK {
		t.Errorf("forge member on org-wide view after the grant = %d, want 200", got)
	}
	if got := f.repoStatus(collaborator, http.MethodGet, "newer"); got != http.StatusNotFound {
		t.Errorf("collaborator on a repo enrolled after sync = %d, want 404", got)
	}

	recorder := httptest.NewRecorder()
	f.srv.handleListRepos(recorder, f.request(collaborator, http.MethodGet, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list repos status = %d: %s", recorder.Code, recorder.Body)
	}
	var listed struct {
		Data []repositoryInventoryEntry `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode repo list: %v", err)
	}
	if len(listed.Data) != 1 || listed.Data[0].Slug != "granted" {
		t.Fatalf("collaborator repo list = %+v, want only granted", listed.Data)
	}
}

// §4.4: viewer and auditor are read-only on repository and org routes;
// developers write, and a collaborator writes only where the forge gave push.
func TestReadOnlyRolesCannotWrite(t *testing.T) {
	f := newAuthzFixture(t, "app", "lib")
	viewer := f.invitedUser(t, "viewer")
	auditor := f.invitedUser(t, "auditor")
	developer := f.invitedUser(t, "developer")
	f.addRepo(t, "other")
	// Synced after "other" exists and without it: the forge says this person
	// reaches the org through two repositories only.
	collaborator := f.forgeUser(t, "developer", map[string]string{"app": "developer", "lib": "viewer"})

	for name, user := range map[string]*store.User{"viewer": viewer, "auditor": auditor} {
		if got := f.repoStatus(user, http.MethodGet, "app"); got != http.StatusOK {
			t.Errorf("%s read = %d, want 200", name, got)
		}
		if got := f.repoStatus(user, http.MethodPost, "app"); got != http.StatusForbidden {
			t.Errorf("%s write via loadAuthorizedRepo = %d, want 403", name, got)
		}
		if got := f.repoWithUserStatus(user, http.MethodPut, "app"); got != http.StatusForbidden {
			t.Errorf("%s write via loadAuthorizedRepoWithUser = %d, want 403", name, got)
		}
		if got := f.orgStatus(user, http.MethodPost); got != http.StatusForbidden {
			t.Errorf("%s org write = %d, want 403", name, got)
		}
	}
	if got := f.repoStatus(developer, http.MethodPost, "app"); got != http.StatusOK {
		t.Errorf("developer write = %d, want 200", got)
	}
	if got := f.orgStatus(developer, http.MethodPost); got != http.StatusOK {
		t.Errorf("developer org write = %d, want 200", got)
	}
	if got := f.repoStatus(collaborator, http.MethodPost, "app"); got != http.StatusOK {
		t.Errorf("collaborator write on pushed repo = %d, want 200", got)
	}
	if got := f.repoStatus(collaborator, http.MethodPost, "lib"); got != http.StatusForbidden {
		t.Errorf("collaborator write on read-only repo = %d, want 403", got)
	}
}

func TestUploadRequiresWritingRole(t *testing.T) {
	f := newAuthzFixture(t, "app")
	viewer := f.invitedUser(t, "viewer")
	developer := f.invitedUser(t, "developer")
	collaborator := f.forgeUser(t, "developer", map[string]string{"app": "developer"})
	f.addRepo(t, "other")
	// The collaborator's sync predates "other"; syncing again after it exists
	// records the gap the forge answered.
	f.syncMembership(t, collaborator, "developer", true)

	input := func(repo string) uploadRequest {
		return uploadRequest{Provider: f.org.Provider, Org: f.org.Slug, Repo: repo}
	}
	if _, _, err := f.srv.resolveUploadAuthorization(f.request(viewer, http.MethodPost, ""), f.srv.queries, input("app")); err == nil {
		t.Error("viewer upload authorized")
	}
	if _, repo, err := f.srv.resolveUploadAuthorization(f.request(developer, http.MethodPost, ""), f.srv.queries, input("app")); err != nil || repo == nil {
		t.Errorf("developer upload refused: %v", err)
	}
	if _, repo, err := f.srv.resolveUploadAuthorization(f.request(collaborator, http.MethodPost, ""), f.srv.queries, input("app")); err != nil || repo == nil {
		t.Errorf("collaborator upload to granted repo refused: %v", err)
	}
	for _, repo := range []string{"other", "brand-new"} {
		if _, _, err := f.srv.resolveUploadAuthorization(f.request(collaborator, http.MethodPost, ""), f.srv.queries, input(repo)); err == nil {
			t.Errorf("collaborator upload to %s authorized", repo)
		}
	}
}

// A9: the status route has no org or repo in its URL, so the token scope is
// checked against the upload's own repository in the handler.
func TestUploadStatusChecksTokenScopeAgainstTheUpload(t *testing.T) {
	f := newAuthzFixture(t, "app")
	owner := f.invitedUser(t, "developer")
	ctx := context.Background()
	ref, err := f.srv.queries.UpsertRef(ctx, f.repo["app"].ID, "main", store.RefTypeBranch, store.UpsertRefOptions{})
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	snapshot, err := f.srv.queries.UpsertSnapshotForBuild(ctx, ref.ID, "abc123", store.SnapshotStatusPending, store.SnapshotBuildMeta{})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	status := func(scope apitoken.Scope) int {
		request := f.request(owner, http.MethodGet, "")
		rctx := chi.RouteContext(request.Context())
		rctx.URLParams.Add("id", snapshot.ID.String())
		request = request.WithContext(internalauth.WithTokenAuth(request.Context(), &internalauth.TokenAuth{
			OwnerType: "user", OwnerID: owner.ID, Scope: scope, Scoped: true,
		}))
		recorder := httptest.NewRecorder()
		f.srv.handleGetUploadStatus(recorder, request)
		return recorder.Code
	}
	uploads := map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapUploads: apitoken.AccessRead}
	if got := status(apitoken.Scope{Org: f.org.Slug, Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll}, Permissions: uploads}); got != http.StatusOK {
		t.Errorf("in-scope token = %d, want 200", got)
	}
	if got := status(apitoken.Scope{Org: "someone-else", Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll}, Permissions: uploads}); got != http.StatusNotFound {
		t.Errorf("token for another org = %d, want 404", got)
	}
}

// Q7: the CVE triage queue and the advisory data a decision authors are
// instance-wide, so org membership — even an org-scoped triager grant — does
// not reach them; an instance admin does, and sees candidates across orgs.
func TestTriageRequiresInstanceAuthority(t *testing.T) {
	mine := newAuthzFixture(t, "app")
	theirs := &authzFixture{srv: mine.srv, repo: map[string]*store.Repository{}}
	ctx := context.Background()
	org, err := mine.srv.queries.CreateOrganization(ctx, uniqueName(t, "other"), uniqueName(t, "other"), "Other", "github")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	theirs.org = org
	theirs.addRepo(t, "svc")

	marker := "zq" + uuid.NewString()[:8]
	attach := func(repo *store.Repository, name string) {
		ref, err := mine.srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{})
		if err != nil {
			t.Fatalf("ref: %v", err)
		}
		snapshot, err := mine.srv.queries.UpsertSnapshotForBuild(ctx, ref.ID, "abc", store.SnapshotStatusComplete, store.SnapshotBuildMeta{})
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		component, err := mine.srv.queries.UpsertComponent(ctx, "pkg:npm/"+name+"@1.0.0", name, "1.0.0", "npm", nil)
		if err != nil {
			t.Fatalf("component: %v", err)
		}
		if err := mine.srv.queries.AttachComponentToSnapshot(ctx, snapshot.ID, component.ID, nil); err != nil {
			t.Fatalf("attach: %v", err)
		}
	}
	attach(mine.repo["app"], marker+"-mine")
	attach(theirs.repo["svc"], marker+"-internal-secret")

	member := mine.invitedUser(t, "admin")
	handlers := map[string]http.HandlerFunc{
		"list":   mine.srv.handleListTriageQueue,
		"get":    mine.srv.handleGetTriageItem,
		"decide": mine.srv.handleDecideTriageItem,
	}
	for name, handler := range handlers {
		recorder := httptest.NewRecorder()
		handler(recorder, mine.request(member, http.MethodGet, ""))
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s by an org admin = %d, want 403", name, recorder.Code)
		}
	}
	if got := mine.srv.triageCandidates(mine.request(member, http.MethodGet, ""), marker); len(got) != 0 {
		t.Errorf("org member got candidates %+v", got)
	}

	mine.srv.cfg.InstanceAdmins = []string{"github:" + member.ProviderID}
	recorder := httptest.NewRecorder()
	mine.srv.handleListTriageQueue(recorder, mine.request(member, http.MethodGet, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("instance admin list = %d: %s", recorder.Code, recorder.Body)
	}
	if got := mine.srv.triageCandidates(mine.request(member, http.MethodGet, ""), marker); len(got) != 2 {
		t.Fatalf("instance admin candidates = %+v, want both orgs", got)
	}
}

// The live-event audience of a repository: members, minus collaborators
// without a grant on it.
func TestRepoAudienceExcludesUngrantedCollaborators(t *testing.T) {
	f := newAuthzFixture(t, "granted", "secret")
	collaborator := f.forgeUser(t, "viewer", map[string]string{"granted": "viewer"})
	member := f.forgeUser(t, "viewer", map[string]string{"granted": "viewer", "secret": "viewer"})
	invited := f.invitedUser(t, "viewer")

	audience := func(slug string) map[uuid.UUID]bool {
		ids, err := f.srv.queries.ListRepoAudienceUserIDs(context.Background(), f.repo[slug].ID)
		if err != nil {
			t.Fatalf("audience: %v", err)
		}
		out := map[uuid.UUID]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	secret := audience("secret")
	if secret[collaborator.ID] {
		t.Error("collaborator without a grant is in the audience")
	}
	if !secret[member.ID] || !secret[invited.ID] {
		t.Errorf("members missing from the audience: %v", secret)
	}
	if !audience("granted")[collaborator.ID] {
		t.Error("collaborator missing from the audience of their own repository")
	}
}

func TestRequirePrincipalMiddleware(t *testing.T) {
	srv := &Server{log: zerolog.Nop()}
	handler := srv.requirePrincipal(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/cwe", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", recorder.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/cwe", nil)
	request = request.WithContext(internalauth.WithUser(request.Context(), &store.User{ID: uuid.New()}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("signed-in status = %d, want 204", recorder.Code)
	}
}
