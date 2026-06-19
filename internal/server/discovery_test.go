package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/objstore"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// testDatabaseURL targets a dedicated test database so integration tests never
// pollute the dev database (hibou). Override with HIBOU_DATABASE_URL.
const testDatabaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"

func TestEqualAccountTrimsAndMatchesCaseInsensitive(t *testing.T) {
	t.Parallel()

	if !equalAccount("  Acme ", "acme") {
		t.Fatal("expected equalAccount to trim and ignore case")
	}
	if equalAccount("acme", "other") {
		t.Fatal("expected different accounts to remain different")
	}
}

func newDiscoveryTestServer(t *testing.T) (*Server, *store.Organization, *store.User, *store.User) {
	t.Helper()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}

	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	queries := store.NewQueries(db)
	ctx := context.Background()
	org, err := queries.CreateOrganization(ctx, uniqueName(t, "discovery-org"), uniqueName(t, "discovery-org"), "Discovery Org", "github")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	admin, err := queries.CreateUser(ctx, uniqueName(t, "admin")+"@example.com", "Admin", "github", uniqueName(t, "admin-user"))
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if err := queries.AddOrgMember(ctx, org.ID, admin.ID, "admin"); err != nil {
		t.Fatalf("add admin member: %v", err)
	}
	member, err := queries.CreateUser(ctx, uniqueName(t, "member")+"@example.com", "Member", "github", uniqueName(t, "member-user"))
	if err != nil {
		t.Fatalf("create member user: %v", err)
	}
	if err := queries.AddOrgMember(ctx, org.ID, member.ID, "viewer"); err != nil {
		t.Fatalf("add member: %v", err)
	}

	forgeProvider := &discoveryTestForgeProvider{id: "github"}
	artifactStore, err := objstore.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	srv := &Server{
		db:       db,
		queries:  queries,
		forges:   map[string]forge.Provider{"github": forgeProvider},
		objStore: artifactStore,
		log:      zerolog.New(io.Discard),
	}

	return srv, org, admin, member
}

func newSyncReposRequest(t *testing.T, user *store.User, provider, slug string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+provider+"/"+slug+"/repos/sync", nil)
	ctx := internalauth.WithUser(req.Context(), user)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", provider)
	rctx.URLParams.Add("slug", slug)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

func uniqueName(t *testing.T, prefix string) string {
	t.Helper()
	return prefix + "-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + uuid.NewString()[:8]
}

type discoveryTestForgeProvider struct {
	id                    string
	installations         []forge.Installation
	installationsErr      error
	repositories          []forge.Repository
	listRepositoriesErr   error
	listRepositoriesCalls int
	webhookPayload        []byte
	webhookPayloadErr     error
	webhookEvent          forge.WebhookEvent
	webhookErr            error
}

func (p *discoveryTestForgeProvider) ID() string {
	return p.id
}

func (p *discoveryTestForgeProvider) Installations(context.Context) ([]forge.Installation, error) {
	return p.installations, p.installationsErr
}

func (p *discoveryTestForgeProvider) ListRepositories(context.Context, forge.ListReposOptions) ([]forge.Repository, error) {
	p.listRepositoriesCalls++
	return p.repositories, p.listRepositoriesErr
}

func (p *discoveryTestForgeProvider) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) ListBranches(context.Context, string, string) ([]forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) GetBranch(context.Context, string, string, string) (*forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) CreateBranch(context.Context, string, string, string, string) error {
	return forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) CreatePullRequest(context.Context, string, string, forge.CreatePROptions) (*forge.PullRequest, error) {
	return nil, forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) CreateCommitStatus(context.Context, string, string, string, forge.CommitStatus) error {
	return forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	if p.webhookPayloadErr != nil {
		return nil, p.webhookPayloadErr
	}
	return append([]byte(nil), p.webhookPayload...), nil
}

func (p *discoveryTestForgeProvider) ParseWebhookEvent(string, []byte) (forge.WebhookEvent, error) {
	if p.webhookErr != nil {
		return nil, p.webhookErr
	}
	if p.webhookEvent != nil {
		return p.webhookEvent, nil
	}
	return nil, forge.ErrUnsupportedWebhookEvent
}

func (p *discoveryTestForgeProvider) OAuth2Config(string) *oauth2.Config {
	return nil
}

func (p *discoveryTestForgeProvider) UserInfo(context.Context, *oauth2.Token) (*forge.UserInfo, error) {
	return nil, forge.ErrNotImplemented
}

func (p *discoveryTestForgeProvider) ListUserAccess(context.Context, *oauth2.Token) (forge.UserAccess, error) {
	return forge.UserAccess{}, nil
}

func discoveryProviderForTest(t *testing.T, srv *Server, providerID string) *discoveryTestForgeProvider {
	if t != nil {
		t.Helper()
	}
	provider, ok := srv.forges[providerID].(*discoveryTestForgeProvider)
	if !ok {
		if t != nil {
			t.Fatalf("provider %q is not discovery test provider", providerID)
		}
		panic("provider is not discovery test provider")
	}
	return provider
}
