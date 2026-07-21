package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	apiauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/orgprovision"
	"github.com/hibouhq/hibou/internal/store"
)

func TestHandleAuthCallbackClaimPendingAdminErrorDoesNotBlockLogin(t *testing.T) {
	t.Parallel()

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

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse token form: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-1",
			"token_type":   "bearer",
		}); err != nil {
			t.Fatalf("encode token response: %v", err)
		}
	}))
	t.Cleanup(tokenServer.Close)

	provider := &oauthCallbackTestProvider{
		id:       "github",
		tokenURL: tokenServer.URL,
		userInfo: &forge.UserInfo{
			ProviderID:  uniqueName(t, "provider-user"),
			Email:       uniqueName(t, "callback") + "@example.com",
			DisplayName: "Callback User",
		},
	}
	authMgr := apiauth.New(apiauth.Config{
		SessionSecret: "test-session-secret",
		BaseURL:       "http://example.com",
		Providers:     map[string]forge.Provider{"github": provider},
	}, store.NewQueries(db))

	srv := &Server{
		authMgr:         authMgr,
		log:             zerolog.New(io.Discard),
		orgProvisionSvc: orgprovision.NewService(orgProvisionClaimErrorStore{}, nil, nil, false, zerolog.New(io.Discard)),
	}

	loginReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login?provider=github", nil)
	loginRecorder := httptest.NewRecorder()
	if err := authMgr.BeginOAuthFlow(loginRecorder, loginReq, "github"); err != nil {
		t.Fatalf("begin oauth flow: %v", err)
	}
	loginResp := loginRecorder.Result()
	t.Cleanup(func() {
		_ = loginResp.Body.Close()
	})
	redirectURL, err := url.Parse(loginResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse oauth redirect: %v", err)
	}
	state := redirectURL.Query().Get("state")
	if state == "" {
		t.Fatal("expected oauth redirect state")
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback", nil)
	callbackReq.URL.RawQuery = url.Values{
		"provider": {"github"},
		"state":    {state},
		"code":     {"test-code"},
	}.Encode()
	for _, cookie := range loginResp.Cookies() {
		callbackReq.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	srv.handleAuthCallback(recorder, callbackReq)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusFound, recorder.Code, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/" {
		t.Fatalf("expected redirect to /, got %q", location)
	}
	if !hasCookieNamed(recorder.Result().Cookies(), "hibou_session") {
		t.Fatal("expected session cookie to be set")
	}
}

type orgProvisionClaimErrorStore struct{}

func (orgProvisionClaimErrorStore) UpsertForgeOrgAdmin(context.Context, string, string, string) (*store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionClaimErrorStore) SetForgeOrgAdminOrg(context.Context, string, string, string, uuid.UUID) error {
	return nil
}

func (orgProvisionClaimErrorStore) MarkForgeOrgAdminGranted(context.Context, uuid.UUID) error {
	return nil
}

func (orgProvisionClaimErrorStore) ListPendingForgeOrgAdminsByUser(context.Context, string, string) ([]store.ForgeOrgAdmin, error) {
	return nil, context.DeadlineExceeded
}

func (orgProvisionClaimErrorStore) ListForgeOrgAdminsByUser(context.Context, string, string) ([]store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionClaimErrorStore) GetForgeOrgAdmin(context.Context, string, string, string) (*store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionClaimErrorStore) ForgeOrgAdminBindingExists(context.Context, string, uuid.UUID) (bool, error) {
	return false, nil
}

func (orgProvisionClaimErrorStore) GetOrganizationByProviderAndSlug(context.Context, string, string) (*store.Organization, error) {
	return nil, nil
}

func (orgProvisionClaimErrorStore) CreateOrganization(context.Context, string, string, string, string) (*store.Organization, error) {
	return nil, nil
}

func (orgProvisionClaimErrorStore) AddOrgMember(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (orgProvisionClaimErrorStore) UpsertOrgMemberRole(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (orgProvisionClaimErrorStore) GetOrgMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return "", nil
}

func (orgProvisionClaimErrorStore) CreateClient(context.Context, uuid.UUID, string, string, json.RawMessage, string, *string, *string, json.RawMessage, json.RawMessage) (*store.Client, error) {
	return nil, nil
}

func (orgProvisionClaimErrorStore) GetUserByProviderID(context.Context, string, string) (*store.User, error) {
	return nil, nil
}

type oauthCallbackTestProvider struct {
	id       string
	tokenURL string
	userInfo *forge.UserInfo
}

func (p *oauthCallbackTestProvider) ID() string { return p.id }

func (p *oauthCallbackTestProvider) Installations(context.Context) ([]forge.Installation, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) ListRepositories(context.Context, forge.ListReposOptions) ([]forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) ListBranches(context.Context, string, string) ([]forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) GetBranch(context.Context, string, string, string) (*forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) CreateBranch(context.Context, string, string, string, string) error {
	return forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) CreatePullRequest(context.Context, string, string, forge.CreatePROptions) (*forge.PullRequest, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) CreateCommitStatus(context.Context, string, string, string, forge.CommitStatus) error {
	return forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) ComparePatch(context.Context, string, string, string, string) (*forge.PatchDiff, error) {
	return nil, nil
}

func (p *oauthCallbackTestProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (p *oauthCallbackTestProvider) ParseWebhookEvent(string, []byte) (forge.WebhookEvent, error) {
	return nil, forge.ErrUnsupportedWebhookEvent
}

func (p *oauthCallbackTestProvider) OAuth2Config(string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://example.com/oauth/authorize",
			TokenURL: p.tokenURL,
		},
	}
}

func (p *oauthCallbackTestProvider) UserInfo(context.Context, *oauth2.Token) (*forge.UserInfo, error) {
	return p.userInfo, nil
}

func (p *oauthCallbackTestProvider) ListUserAccess(context.Context, *oauth2.Token) (forge.UserAccess, error) {
	return forge.UserAccess{}, nil
}

func hasCookieNamed(cookies []*http.Cookie, name string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return true
		}
	}
	return false
}
