package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

func TestHandleEnrollRepoNormalizesNumericProviderID(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	providerID := org.Slug + "/api"

	result, err := srv.queries.UpsertForgeRepository(context.Background(), store.ForgeRepository{
		Provider:       org.Provider,
		AccountLogin:   org.Slug,
		Owner:          org.Slug,
		Name:           "api",
		FullName:       providerID,
		ProviderRepoID: strptr("12345"),
		DefaultBranch:  "main",
		HTMLURL:        "https://github.com/" + providerID,
	})
	if err != nil {
		t.Fatalf("UpsertForgeRepository(api): %v", err)
	}
	if result == nil || result.Repository == nil {
		t.Fatal("UpsertForgeRepository(api) returned nil repository")
	}

	recorder := httptest.NewRecorder()
	srv.handleEnrollRepo(recorder, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{
		"name":           "api",
		"slug":           "api",
		"provider_id":    "12345",
		"default_branch": "main",
	}))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("handleEnrollRepo() status = %d, want %d", recorder.Code, http.StatusCreated)
	}

	repo, err := srv.queries.GetRepositoryBySlug(context.Background(), org.ID, "api")
	if err != nil {
		t.Fatalf("GetRepositoryBySlug(api): %v", err)
	}
	if repo == nil {
		t.Fatal("expected enrolled repository to be stored")
	}
	if repo.ProviderID != providerID {
		t.Fatalf("stored provider_id = %q, want %q", repo.ProviderID, providerID)
	}
}

func TestHandleEnrollRepoKeepsProviderIDWhenNotInInventory(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	providerID := org.Slug + "/standalone"

	recorder := httptest.NewRecorder()
	srv.handleEnrollRepo(recorder, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{
		"name":           "standalone",
		"slug":           "standalone",
		"provider_id":    providerID,
		"default_branch": "main",
	}))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("handleEnrollRepo() status = %d, want %d", recorder.Code, http.StatusCreated)
	}

	repo, err := srv.queries.GetRepositoryBySlug(context.Background(), org.ID, "standalone")
	if err != nil {
		t.Fatalf("GetRepositoryBySlug(standalone): %v", err)
	}
	if repo == nil {
		t.Fatal("expected enrolled repository to be stored")
	}
	if repo.ProviderID != providerID {
		t.Fatalf("stored provider_id = %q, want %q", repo.ProviderID, providerID)
	}
}

func TestHandleEnrollRepoNormalizesProviderKeyCase(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	providerID := org.Slug + "/api"

	result, err := srv.queries.UpsertForgeRepository(context.Background(), store.ForgeRepository{
		Provider:      org.Provider,
		AccountLogin:  "foo.bar",
		Owner:         org.Slug,
		Name:          "api",
		FullName:      providerID,
		DefaultBranch: "main",
		HTMLURL:       "https://github.com/" + providerID,
	})
	if err != nil {
		t.Fatalf("UpsertForgeRepository(api): %v", err)
	}
	if result == nil || result.Repository == nil {
		t.Fatal("UpsertForgeRepository(api) returned nil repository")
	}

	recorder := httptest.NewRecorder()
	srv.handleEnrollRepo(recorder, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{
		"name":           "api",
		"slug":           "api",
		"provider_id":    strings.ToUpper(providerID),
		"default_branch": "main",
	}))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("handleEnrollRepo() status = %d, want %d", recorder.Code, http.StatusCreated)
	}

	repo, err := srv.queries.GetRepositoryBySlug(context.Background(), org.ID, "api")
	if err != nil {
		t.Fatalf("GetRepositoryBySlug(api): %v", err)
	}
	if repo == nil {
		t.Fatal("expected enrolled repository to be stored")
	}
	if repo.ProviderID != providerID {
		t.Fatalf("stored provider_id = %q, want %q", repo.ProviderID, providerID)
	}
}

func newEnrollRequest(t *testing.T, user *store.User, provider, slug string, body any) *http.Request {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal enroll body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/"+provider+"/"+slug+"/repos", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	ctx := internalauth.WithUser(req.Context(), user)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", provider)
	rctx.URLParams.Add("slug", slug)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

func strptr(value string) *string {
	return &value
}
