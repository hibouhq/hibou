package permissionsync

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func TestSyncUserProjectsAndPrunesMemberships(t *testing.T) {
	t.Parallel()

	user := testUser()
	keepOrg := testOrg("github", "acme")
	prunedOrgID := uuid.New()
	keepRepo := testRepo(keepOrg.ID, "alpha")
	storeFake := &fakeStore{
		orgsBySlug:          map[string]*store.Organization{"github/acme": keepOrg},
		reposByOrgAndSlug:   map[string]*store.Repository{repoKey(keepOrg.ID, "alpha"): keepRepo},
		existingMemberships: []store.ForgeOrgMembership{{OrgID: keepOrg.ID, UserID: user.ID, Role: "viewer"}, {OrgID: prunedOrgID, UserID: user.ID, Role: "admin"}},
	}
	rbacFake := &fakeRBAC{}
	svc := NewService(storeFake, rbacFake, map[string]forge.Provider{
		"github": fakeProvider{access: forge.UserAccess{
			Orgs:  []forge.UserOrgAccess{{AccountLogin: "Acme", Level: "push"}},
			Repos: []forge.UserRepoAccess{{AccountLogin: "Acme", Name: "alpha", Level: "pull"}, {AccountLogin: "Acme", Name: "missing", Level: "push"}},
		}},
	}, zerolog.Nop())

	if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("SyncUser() error = %v", err)
	}

	if len(storeFake.upsertOrgMembers) != 1 {
		t.Fatalf("expected one org upsert, got %#v", storeFake.upsertOrgMembers)
	}
	if got := storeFake.upsertOrgMembers[0].role; got != "developer" {
		t.Fatalf("org role = %q, want developer", got)
	}
	if len(storeFake.prunedOrgIDs) != 1 || storeFake.prunedOrgIDs[0] != keepOrg.ID {
		t.Fatalf("pruned keep org ids = %#v, want [%s]", storeFake.prunedOrgIDs, keepOrg.ID)
	}
	if len(rbacFake.added) != 1 || rbacFake.added[0].role != "developer" {
		t.Fatalf("rbac added = %#v", rbacFake.added)
	}
	if len(rbacFake.removed) != 2 {
		t.Fatalf("rbac removed = %#v, want prior role change plus pruned org", rbacFake.removed)
	}
	if len(storeFake.upsertRepoAccess) != 1 || storeFake.upsertRepoAccess[0].role != "viewer" {
		t.Fatalf("repo access upserts = %#v", storeFake.upsertRepoAccess)
	}
	if len(storeFake.prunedRepoIDs) != 1 || storeFake.prunedRepoIDs[0] != keepRepo.ID {
		t.Fatalf("pruned keep repo ids = %#v, want [%s]", storeFake.prunedRepoIDs, keepRepo.ID)
	}
}

func TestSyncUserMapsWriteTierToDeveloper(t *testing.T) {
	t.Parallel()

	user := testUser()
	org := testOrg("github", "acme")
	storeFake := &fakeStore{orgsBySlug: map[string]*store.Organization{"github/acme": org}}
	svc := NewService(storeFake, &fakeRBAC{}, map[string]forge.Provider{
		"github": fakeProvider{access: forge.UserAccess{Orgs: []forge.UserOrgAccess{{AccountLogin: "Acme", Level: "push"}}}},
	}, zerolog.Nop())

	if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("SyncUser() error = %v", err)
	}
	if len(storeFake.upsertOrgMembers) != 1 || storeFake.upsertOrgMembers[0].role != "developer" {
		t.Fatalf("org upserts = %#v", storeFake.upsertOrgMembers)
	}
}

func TestSyncUserSkipsUnknownOrganizations(t *testing.T) {
	t.Parallel()

	user := testUser()
	storeFake := &fakeStore{}
	svc := NewService(storeFake, &fakeRBAC{}, map[string]forge.Provider{
		"github": fakeProvider{access: forge.UserAccess{
			Orgs:  []forge.UserOrgAccess{{AccountLogin: "Ghost Org", Level: "admin"}},
			Repos: []forge.UserRepoAccess{{AccountLogin: "Ghost Org", Name: "repo", Level: "push"}},
		}},
	}, zerolog.Nop())

	if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("SyncUser() error = %v", err)
	}
	if len(storeFake.upsertOrgMembers) != 0 {
		t.Fatalf("unexpected org upserts %#v", storeFake.upsertOrgMembers)
	}
	if len(storeFake.upsertRepoAccess) != 0 {
		t.Fatalf("unexpected repo upserts %#v", storeFake.upsertRepoAccess)
	}
	if storeFake.lookupOrgCalls != 1 {
		t.Fatalf("lookup org calls = %d, want 1", storeFake.lookupOrgCalls)
	}
}

func TestSyncUserProjectsOnlyEnrolledRepos(t *testing.T) {
	t.Parallel()

	user := testUser()
	org := testOrg("github", "acme")
	repo := testRepo(org.ID, "alpha")
	storeFake := &fakeStore{
		orgsBySlug:        map[string]*store.Organization{"github/acme": org},
		reposByOrgAndSlug: map[string]*store.Repository{repoKey(org.ID, "alpha"): repo},
	}
	svc := NewService(storeFake, &fakeRBAC{}, map[string]forge.Provider{
		"github": fakeProvider{access: forge.UserAccess{
			Orgs:  []forge.UserOrgAccess{{AccountLogin: "Acme", Level: "member"}},
			Repos: []forge.UserRepoAccess{{AccountLogin: "Acme", Name: "alpha", Level: "push"}, {AccountLogin: "Acme", Name: "beta", Level: "admin"}},
		}},
	}, zerolog.Nop())

	if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
		t.Fatalf("SyncUser() error = %v", err)
	}
	if len(storeFake.upsertRepoAccess) != 1 || storeFake.upsertRepoAccess[0].repoID != repo.ID || storeFake.upsertRepoAccess[0].role != "developer" {
		t.Fatalf("repo access upserts = %#v", storeFake.upsertRepoAccess)
	}
	if len(storeFake.prunedRepoIDs) != 1 || storeFake.prunedRepoIDs[0] != repo.ID {
		t.Fatalf("repo prune keep ids = %#v", storeFake.prunedRepoIDs)
	}
}

func TestSyncUserReturnsProviderError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	svc := NewService(&fakeStore{}, &fakeRBAC{}, map[string]forge.Provider{
		"github": fakeProvider{err: wantErr},
	}, zerolog.Nop())

	err := svc.SyncUser(context.Background(), testUser(), "github", &oauth2.Token{AccessToken: "token"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("SyncUser() error = %v, want %v", err, wantErr)
	}
}

func TestSyncUserReordersRBACRoleChangesSafely(t *testing.T) {
	t.Parallel()

	user := testUser()
	org := testOrg("github", "acme")

	t.Run("changed role adds new before removing old", func(t *testing.T) {
		t.Parallel()

		storeFake := &fakeStore{
			orgsBySlug:          map[string]*store.Organization{"github/acme": org},
			existingMemberships: []store.ForgeOrgMembership{{OrgID: org.ID, UserID: user.ID, Role: "developer"}},
		}
		rbacFake := &fakeRBAC{}
		svc := NewService(storeFake, rbacFake, map[string]forge.Provider{
			"github": fakeProvider{access: forge.UserAccess{Orgs: []forge.UserOrgAccess{{AccountLogin: "Acme", Level: "admin"}}}},
		}, zerolog.Nop())

		if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
			t.Fatalf("SyncUser() error = %v", err)
		}
		if len(rbacFake.added) != 1 || rbacFake.added[0].role != "admin" {
			t.Fatalf("rbac added = %#v", rbacFake.added)
		}
		if len(rbacFake.removed) != 1 || rbacFake.removed[0].role != "developer" {
			t.Fatalf("rbac removed = %#v", rbacFake.removed)
		}
	})

	t.Run("failed add keeps old role", func(t *testing.T) {
		t.Parallel()

		storeFake := &fakeStore{
			orgsBySlug:          map[string]*store.Organization{"github/acme": org},
			existingMemberships: []store.ForgeOrgMembership{{OrgID: org.ID, UserID: user.ID, Role: "developer"}},
		}
		rbacFake := &fakeRBAC{addErr: errors.New("add failed")}
		svc := NewService(storeFake, rbacFake, map[string]forge.Provider{
			"github": fakeProvider{access: forge.UserAccess{Orgs: []forge.UserOrgAccess{{AccountLogin: "Acme", Level: "admin"}}}},
		}, zerolog.Nop())

		if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
			t.Fatalf("SyncUser() error = %v", err)
		}
		if len(rbacFake.added) != 1 || rbacFake.added[0].role != "admin" {
			t.Fatalf("rbac added = %#v", rbacFake.added)
		}
		if len(rbacFake.removed) != 0 {
			t.Fatalf("old role should be retained when add fails, removed = %#v", rbacFake.removed)
		}
	})

	t.Run("same role is no rbac churn", func(t *testing.T) {
		t.Parallel()

		storeFake := &fakeStore{
			orgsBySlug:          map[string]*store.Organization{"github/acme": org},
			existingMemberships: []store.ForgeOrgMembership{{OrgID: org.ID, UserID: user.ID, Role: "admin"}},
		}
		rbacFake := &fakeRBAC{}
		svc := NewService(storeFake, rbacFake, map[string]forge.Provider{
			"github": fakeProvider{access: forge.UserAccess{Orgs: []forge.UserOrgAccess{{AccountLogin: "Acme", Level: "admin"}}}},
		}, zerolog.Nop())

		if err := svc.SyncUser(context.Background(), user, "github", &oauth2.Token{AccessToken: "token"}); err != nil {
			t.Fatalf("SyncUser() error = %v", err)
		}
		if len(rbacFake.added) != 0 {
			t.Fatalf("rbac added = %#v", rbacFake.added)
		}
		if len(rbacFake.removed) != 0 {
			t.Fatalf("rbac removed = %#v", rbacFake.removed)
		}
	})
}

type fakeStore struct {
	orgsBySlug          map[string]*store.Organization
	reposByOrgAndSlug   map[string]*store.Repository
	existingMemberships []store.ForgeOrgMembership
	upsertOrgMembers    []membershipCall
	prunedOrgIDs        []uuid.UUID
	upsertRepoAccess    []repoAccessCall
	prunedRepoIDs       []uuid.UUID
	lookupOrgCalls      int
}

type membershipCall struct {
	orgID  uuid.UUID
	userID uuid.UUID
	role   string
}

type repoAccessCall struct {
	userID uuid.UUID
	repoID uuid.UUID
	role   string
}

func (f *fakeStore) GetOrganizationByProviderAndSlug(_ context.Context, provider, slug string) (*store.Organization, error) {
	f.lookupOrgCalls++
	return f.orgsBySlug[provider+"/"+slug], nil
}

func (f *fakeStore) UpsertForgeOrgMember(_ context.Context, orgID, userID uuid.UUID, role string) error {
	f.upsertOrgMembers = append(f.upsertOrgMembers, membershipCall{orgID: orgID, userID: userID, role: role})
	return nil
}

func (f *fakeStore) ListForgeOrgMembershipsByUser(context.Context, uuid.UUID) ([]store.ForgeOrgMembership, error) {
	return append([]store.ForgeOrgMembership(nil), f.existingMemberships...), nil
}

func (f *fakeStore) PruneForgeOrgMembersForUser(_ context.Context, _ uuid.UUID, keepOrgIDs []uuid.UUID) error {
	f.prunedOrgIDs = append([]uuid.UUID(nil), keepOrgIDs...)
	return nil
}

func (f *fakeStore) GetRepositoryBySlug(_ context.Context, orgID uuid.UUID, slug string) (*store.Repository, error) {
	return f.reposByOrgAndSlug[repoKey(orgID, slug)], nil
}

func (f *fakeStore) UpsertForgeUserRepoAccess(_ context.Context, userID, repoID uuid.UUID, role string) error {
	f.upsertRepoAccess = append(f.upsertRepoAccess, repoAccessCall{userID: userID, repoID: repoID, role: role})
	return nil
}

func (f *fakeStore) PruneForgeUserRepoAccess(_ context.Context, _ uuid.UUID, keepRepoIDs []uuid.UUID) error {
	f.prunedRepoIDs = append([]uuid.UUID(nil), keepRepoIDs...)
	return nil
}

type fakeRBAC struct {
	added   []membershipCall
	removed []membershipCall
	addErr  error
}

func (f *fakeRBAC) AddRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	f.added = append(f.added, membershipCall{orgID: orgID, userID: userID, role: role})
	return f.addErr
}

func (f *fakeRBAC) RemoveRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	f.removed = append(f.removed, membershipCall{orgID: orgID, userID: userID, role: role})
	return nil
}

type fakeProvider struct {
	access forge.UserAccess
	err    error
}

func (f fakeProvider) ID() string                                                  { return "github" }
func (f fakeProvider) Installations(context.Context) ([]forge.Installation, error) { return nil, nil }
func (f fakeProvider) ListRepositories(context.Context, forge.ListReposOptions) ([]forge.Repository, error) {
	return nil, nil
}
func (f fakeProvider) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return nil, nil
}
func (f fakeProvider) ListBranches(context.Context, string, string) ([]forge.Branch, error) {
	return nil, nil
}
func (f fakeProvider) GetBranch(context.Context, string, string, string) (*forge.Branch, error) {
	return nil, nil
}
func (f fakeProvider) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, nil
}
func (f fakeProvider) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return nil
}
func (f fakeProvider) CreateBranch(context.Context, string, string, string, string) error { return nil }
func (f fakeProvider) CreatePullRequest(context.Context, string, string, forge.CreatePROptions) (*forge.PullRequest, error) {
	return nil, nil
}
func (f fakeProvider) CreateCommitStatus(context.Context, string, string, string, forge.CommitStatus) error {
	return nil
}
func (f fakeProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) { return nil, nil }
func (f fakeProvider) ParseWebhookEvent(string, []byte) (forge.WebhookEvent, error) { return nil, nil }
func (f fakeProvider) OAuth2Config(string) *oauth2.Config                           { return nil }
func (f fakeProvider) UserInfo(context.Context, *oauth2.Token) (*forge.UserInfo, error) {
	return nil, nil
}
func (f fakeProvider) ListUserAccess(context.Context, *oauth2.Token) (forge.UserAccess, error) {
	if f.err != nil {
		return forge.UserAccess{}, f.err
	}
	return f.access, nil
}

func repoKey(orgID uuid.UUID, slug string) string {
	return orgID.String() + "/" + slug
}

func testUser() *store.User {
	now := time.Now().UTC()
	return &store.User{ID: uuid.New(), Provider: "github", ProviderID: "42", CreatedAt: now, UpdatedAt: now}
}

func testOrg(provider, slug string) *store.Organization {
	now := time.Now().UTC()
	return &store.Organization{ID: uuid.New(), Provider: provider, Slug: slug, CreatedAt: now, UpdatedAt: now}
}

func testRepo(orgID uuid.UUID, slug string) *store.Repository {
	now := time.Now().UTC()
	return &store.Repository{ID: uuid.New(), OrgID: orgID, Slug: slug, Name: slug, CreatedAt: now, UpdatedAt: now}
}
