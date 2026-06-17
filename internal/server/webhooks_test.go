package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/repoinventory"
)

func TestHandleWebhookReturnsSuccessForUnregisteredEvent(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{id: "github", webhookPayload: []byte(`{}`), webhookEvent: testWebhookEvent{eventType: "repository"}}
	srv := &Server{forges: map[string]forge.Provider{"github": provider}, log: zerolog.New(io.Discard)}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", http.NoBody)
	req.Header.Set("X-GitHub-Event", "repository")
	req = req.WithContext(withProviderRoute(req, "github").Context())
	recorder := httptest.NewRecorder()

	srv.handleWebhook(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
}

func TestHandleWebhookDispatchesRegisteredHandler(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{id: "github", webhookPayload: []byte(`{}`), webhookEvent: testWebhookEvent{eventType: "repository"}}
	srv := &Server{forges: map[string]forge.Provider{"github": provider}, log: zerolog.New(io.Discard), webhookHandlers: map[string][]forgeEventHandler{}}
	called := false
	srv.registerWebhookHandler("repository", func(_ context.Context, providerID string, event forge.WebhookEvent) error {
		called = providerID == "github" && event.EventType() == "repository"
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", http.NoBody)
	req.Header.Set("X-GitHub-Event", "repository")
	req = req.WithContext(withProviderRoute(req, "github").Context())
	recorder := httptest.NewRecorder()

	srv.handleWebhook(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	if !called {
		t.Fatal("expected registered webhook handler to be called")
	}
}

func TestHandleWebhookReturnsServerErrorWhenRegisteredHandlerFails(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{id: "github", webhookPayload: []byte(`{}`), webhookEvent: testWebhookEvent{eventType: "repository"}}
	srv := &Server{forges: map[string]forge.Provider{"github": provider}, log: zerolog.New(io.Discard), webhookHandlers: map[string][]forgeEventHandler{}}
	srv.registerWebhookHandler("repository", func(_ context.Context, _ string, _ forge.WebhookEvent) error {
		return errors.New("boom")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", http.NoBody)
	req.Header.Set("X-GitHub-Event", "repository")
	req = req.WithContext(withProviderRoute(req, "github").Context())
	recorder := httptest.NewRecorder()

	srv.handleWebhook(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d: %s", http.StatusInternalServerError, recorder.Code, recorder.Body.String())
	}
}

func TestHandleWebhookTreatsUnsupportedProviderEventAsNoop(t *testing.T) {
	t.Parallel()

	provider := &discoveryTestForgeProvider{id: "github", webhookPayload: []byte(`{}`), webhookErr: forge.ErrUnsupportedWebhookEvent}
	srv := &Server{forges: map[string]forge.Provider{"github": provider}, log: zerolog.New(io.Discard)}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", http.NoBody)
	req.Header.Set("X-GitHub-Event", "unknown")
	req = req.WithContext(withProviderRoute(req, "github").Context())
	recorder := httptest.NewRecorder()

	srv.handleWebhook(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
}

func TestHandleSyncReposRequiresAdmin(t *testing.T) {
	srv, org, _, member := newDiscoveryTestServer(t)
	provider := discoveryProviderForTest(t, srv, org.Provider)
	provider.installations = []forge.Installation{{ID: 7, AccountName: org.Slug, AccountType: "Organization"}}
	provider.repositories = []forge.Repository{{Owner: org.Slug, Name: "api", FullName: org.Slug + "/api"}}
	srv.inventorySvc = repoinventory.NewService(srv.queries, srv.forges, srv.log)

	req := newSyncReposRequest(t, member, org.Provider, org.Slug)
	recorder := httptest.NewRecorder()

	srv.handleSyncRepos(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d: %s", http.StatusForbidden, recorder.Code, recorder.Body.String())
	}
}

func TestHandleSyncReposReturnsRepositoryCount(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	provider := discoveryProviderForTest(t, srv, org.Provider)
	provider.installations = []forge.Installation{{ID: 7, AccountName: org.Slug, AccountType: "Organization"}}
	provider.repositories = []forge.Repository{{Owner: org.Slug, Name: "api", FullName: org.Slug + "/api"}, {Owner: "other", Name: "skip", FullName: "other/skip"}}
	srv.inventorySvc = repoinventory.NewService(srv.queries, srv.forges, srv.log)

	req := newSyncReposRequest(t, admin, org.Provider, org.Slug)
	recorder := httptest.NewRecorder()

	srv.handleSyncRepos(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data syncReposResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Data.RepoCount != 1 {
		t.Fatalf("expected repo_count 1, got %d", response.Data.RepoCount)
	}
}

type testWebhookEvent struct{ eventType string }

func (e testWebhookEvent) EventType() string { return e.eventType }

func withProviderRoute(req *http.Request, provider string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", provider)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}
