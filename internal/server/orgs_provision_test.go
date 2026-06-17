package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/orgprovision"
	"github.com/hibouhq/hibou/internal/store"
)

func TestHandleCreateOrgForgeProvisionGateDeniesUnknownInstaller(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{
		id:            "github",
		installations: []forge.Installation{{ID: 1, AccountName: "Acme", AccountType: "Organization"}},
	}
	user := &store.User{ID: uniqueUUID(t), Provider: "github", ProviderID: "requester-1", Email: "requester@example.com", DisplayName: "Requester"}
	log := zerolog.New(io.Discard)
	srv := &Server{
		forges:          map[string]forge.Provider{"github": provider},
		orgProvisionSvc: orgprovision.NewService(orgProvisionDenyStore{}, nil, map[string]forge.Provider{"github": provider}, false, log),
		log:             log,
	}

	recorder := httptest.NewRecorder()
	srv.handleCreateOrg(recorder, newCreateOrgRequest(t, user, createOrgRequest{Name: "Acme", Slug: "acme", DisplayName: "Acme", Provider: "github"}))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d: %s", http.StatusForbidden, recorder.Code, recorder.Body.String())
	}
}

func TestHandleCreateOrgNonForgePathStillWorks(t *testing.T) {
	t.Parallel()

	srv, _, admin, _ := newDiscoveryTestServer(t)
	srv.forges = map[string]forge.Provider{}
	srv.orgProvisionSvc = orgprovision.NewService(orgprovision.NewStoreAdapter(srv.queries), nil, nil, false, srv.log)

	recorder := httptest.NewRecorder()
	slug := uniqueName(t, "fresh-org")
	srv.handleCreateOrg(recorder, newCreateOrgRequest(t, admin, createOrgRequest{Name: slug, Slug: slug, DisplayName: "Fresh Org", Provider: "github"}))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, recorder.Code, recorder.Body.String())
	}
}

func TestHandleCreateOrgForgeProvisionGateAllowsVerifiedInstaller(t *testing.T) {
	t.Parallel()

	srv, _, _, _ := newDiscoveryTestServer(t)
	accountSlug := "acme-" + uuid.NewString()[:8]
	provider := &discoveryTestForgeProvider{
		id:            "github",
		installations: []forge.Installation{{ID: 1, AccountName: accountSlug, AccountType: "Organization"}},
	}
	requesterProviderID := uniqueName(t, "requester-user")
	user, err := srv.queries.CreateUser(context.Background(), uniqueName(t, "requester")+"@example.com", "Requester", "github", requesterProviderID)
	if err != nil {
		t.Fatalf("create requester user: %v", err)
	}
	log := zerolog.New(io.Discard)
	srv.forges = map[string]forge.Provider{"github": provider}
	srv.orgProvisionSvc = orgprovision.NewService(orgProvisionAuthorizeStore{
		admins: map[string]*store.ForgeOrgAdmin{
			forgeProvisionAdminKey("github", accountSlug, requesterProviderID): {
				ID:             uuid.New(),
				Provider:       "github",
				Account:        accountSlug,
				ProviderUserID: requesterProviderID,
			},
		},
	}, nil, map[string]forge.Provider{"github": provider}, false, log)
	srv.log = log

	recorder := httptest.NewRecorder()
	srv.handleCreateOrg(recorder, newCreateOrgRequest(t, user, createOrgRequest{Name: accountSlug, Slug: accountSlug, DisplayName: accountSlug, Provider: "github"}))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, recorder.Code, recorder.Body.String())
	}
}

func TestHandleListOnboardableOrgsRequiresAuth(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{id: "github"}
	log := zerolog.New(io.Discard)
	srv := &Server{
		forges:          map[string]forge.Provider{"github": provider},
		orgProvisionSvc: orgprovision.NewService(orgProvisionDenyStore{}, nil, map[string]forge.Provider{"github": provider}, false, log),
		log:             log,
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/onboardable", nil)
	srv.handleListOnboardableOrgs(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d: %s", http.StatusUnauthorized, recorder.Code, recorder.Body.String())
	}
}

func TestHandleListOnboardableOrgsReturnsUserAccounts(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{
		id:            "github",
		installations: []forge.Installation{{ID: 1, AccountName: "Acme", AccountType: "Organization"}},
	}
	log := zerolog.New(io.Discard)
	user := &store.User{ID: uniqueUUID(t), Provider: "github", ProviderID: "requester-1", Email: "requester@example.com", DisplayName: "Requester"}
	srv := &Server{
		forges: map[string]forge.Provider{"github": provider},
		orgProvisionSvc: orgprovision.NewService(orgProvisionAuthorizeStore{
			admins: map[string]*store.ForgeOrgAdmin{
				forgeProvisionAdminKey("github", "Acme", "requester-1"): {
					ID:             uuid.New(),
					Provider:       "github",
					Account:        "acme",
					ProviderUserID: "requester-1",
				},
			},
		}, nil, map[string]forge.Provider{"github": provider}, false, log),
		log: log,
	}

	recorder := httptest.NewRecorder()
	srv.handleListOnboardableOrgs(recorder, newOnboardableRequest(t, user))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data []orgprovision.OnboardableAccount `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Data) != 1 {
		t.Fatalf("expected 1 onboardable account, got %d", len(payload.Data))
	}
	if payload.Data[0].Status != "importable" || payload.Data[0].Slug != "acme" {
		t.Fatalf("unexpected onboardable payload: %+v", payload.Data[0])
	}
}

func newCreateOrgRequest(t *testing.T, user *store.User, input createOrgRequest) *http.Request {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal create org request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs", bytes.NewReader(body))
	ctx := internalauth.WithUser(req.Context(), user)
	rctx := chi.NewRouteContext()
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

func newOnboardableRequest(t *testing.T, user *store.User) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/onboardable", nil)
	ctx := internalauth.WithUser(req.Context(), user)
	return req.WithContext(ctx)
}

func uniqueUUID(t *testing.T) uuid.UUID {
	t.Helper()
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(t.Name()))
}

type orgProvisionDenyStore struct{}

func (orgProvisionDenyStore) UpsertForgeOrgAdmin(context.Context, string, string, string) (*store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionDenyStore) SetForgeOrgAdminOrg(context.Context, string, string, string, uuid.UUID) error {
	return nil
}

func (orgProvisionDenyStore) MarkForgeOrgAdminGranted(context.Context, uuid.UUID) error {
	return nil
}

func (orgProvisionDenyStore) ListPendingForgeOrgAdminsByUser(context.Context, string, string) ([]store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionDenyStore) ListForgeOrgAdminsByUser(context.Context, string, string) ([]store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionDenyStore) GetForgeOrgAdmin(context.Context, string, string, string) (*store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (orgProvisionDenyStore) ForgeOrgAdminBindingExists(context.Context, string, uuid.UUID) (bool, error) {
	return false, nil
}

func (orgProvisionDenyStore) GetOrganizationByProviderAndSlug(context.Context, string, string) (*store.Organization, error) {
	return nil, nil
}

func (orgProvisionDenyStore) CreateOrganization(context.Context, string, string, string, string) (*store.Organization, error) {
	return nil, nil
}

func (orgProvisionDenyStore) AddOrgMember(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (orgProvisionDenyStore) UpsertOrgMemberRole(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (orgProvisionDenyStore) RemoveOrgMember(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

func (orgProvisionDenyStore) GetOrgMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return "", nil
}

func (orgProvisionDenyStore) CreateClient(context.Context, uuid.UUID, string, string, json.RawMessage, string, *string, *string, json.RawMessage, json.RawMessage) (*store.Client, error) {
	return nil, nil
}

func (orgProvisionDenyStore) GetUserByProviderID(context.Context, string, string) (*store.User, error) {
	return nil, nil
}

type orgProvisionAuthorizeStore struct {
	admins map[string]*store.ForgeOrgAdmin
}

func (s orgProvisionAuthorizeStore) UpsertForgeOrgAdmin(context.Context, string, string, string) (*store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (s orgProvisionAuthorizeStore) SetForgeOrgAdminOrg(context.Context, string, string, string, uuid.UUID) error {
	return nil
}

func (s orgProvisionAuthorizeStore) MarkForgeOrgAdminGranted(context.Context, uuid.UUID) error {
	return nil
}

func (s orgProvisionAuthorizeStore) ListPendingForgeOrgAdminsByUser(context.Context, string, string) ([]store.ForgeOrgAdmin, error) {
	return nil, nil
}

func (s orgProvisionAuthorizeStore) ListForgeOrgAdminsByUser(_ context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error) {
	rows := make([]store.ForgeOrgAdmin, 0)
	for _, admin := range s.admins {
		if admin.Provider == provider && admin.ProviderUserID == providerUserID {
			rows = append(rows, *admin)
		}
	}
	return rows, nil
}

func (s orgProvisionAuthorizeStore) GetForgeOrgAdmin(_ context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error) {
	admin := s.admins[forgeProvisionAdminKey(provider, account, providerUserID)]
	if admin == nil {
		return nil, nil
	}
	clone := *admin
	return &clone, nil
}

func (s orgProvisionAuthorizeStore) ForgeOrgAdminBindingExists(context.Context, string, uuid.UUID) (bool, error) {
	return false, nil
}

func (s orgProvisionAuthorizeStore) GetOrganizationByProviderAndSlug(context.Context, string, string) (*store.Organization, error) {
	return nil, nil
}

func (s orgProvisionAuthorizeStore) CreateOrganization(context.Context, string, string, string, string) (*store.Organization, error) {
	return nil, nil
}

func (s orgProvisionAuthorizeStore) AddOrgMember(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (s orgProvisionAuthorizeStore) UpsertOrgMemberRole(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}

func (s orgProvisionAuthorizeStore) RemoveOrgMember(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

func (s orgProvisionAuthorizeStore) GetOrgMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return "", nil
}

func (s orgProvisionAuthorizeStore) CreateClient(context.Context, uuid.UUID, string, string, json.RawMessage, string, *string, *string, json.RawMessage, json.RawMessage) (*store.Client, error) {
	return nil, nil
}

func (s orgProvisionAuthorizeStore) GetUserByProviderID(context.Context, string, string) (*store.User, error) {
	return nil, nil
}

func forgeProvisionAdminKey(provider, account, providerUserID string) string {
	return provider + ":" + strings.ToLower(strings.TrimSpace(account)) + ":" + providerUserID
}
