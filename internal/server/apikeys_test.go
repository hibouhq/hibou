package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
)

func TestAPIKeyMutationRequiresSession(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	body := `{"name":"test key","expires_at":"` + time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339) +
		`","scopes":{"org":"` + org.Slug + `","repos":{"mode":"all"},"permissions":{"coverage":"read"}}}`
	newRequest := func(method, path string, bearer bool) *http.Request {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		ctx := internalauth.WithUser(req.Context(), admin)
		if bearer {
			ctx = internalauth.WithTokenAuth(ctx, &internalauth.TokenAuth{})
		}
		return req.WithContext(ctx)
	}

	createBearer := httptest.NewRecorder()
	srv.handleCreateAPIKey(createBearer, newRequest(http.MethodPost, "/api/v1/users/me/api-keys", true))
	if createBearer.Code != http.StatusForbidden {
		t.Fatalf("bearer create = %d: %s", createBearer.Code, createBearer.Body.String())
	}

	createSession := httptest.NewRecorder()
	srv.handleCreateAPIKey(createSession, newRequest(http.MethodPost, "/api/v1/users/me/api-keys", false))
	if createSession.Code != http.StatusCreated {
		t.Fatalf("session create = %d: %s", createSession.Code, createSession.Body.String())
	}

	keys, err := srv.queries.ListAPIKeysByUser(context.Background(), admin.ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByUser: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("created key count = %d, want 1", len(keys))
	}
	keyID := keys[0].ID
	deleteBearer := httptest.NewRecorder()
	srv.handleDeleteAPIKey(deleteBearer, apiKeyRequest(t, newRequest(http.MethodDelete, "/api/v1/users/me/api-keys/"+keyID.String(), true), keyID))
	if deleteBearer.Code != http.StatusForbidden {
		t.Fatalf("bearer delete = %d: %s", deleteBearer.Code, deleteBearer.Body.String())
	}

	deleteSession := httptest.NewRecorder()
	srv.handleDeleteAPIKey(deleteSession, apiKeyRequest(t, newRequest(http.MethodDelete, "/api/v1/users/me/api-keys/"+keyID.String(), false), keyID))
	if deleteSession.Code != http.StatusNoContent {
		t.Fatalf("session delete = %d: %s", deleteSession.Code, deleteSession.Body.String())
	}
}

func apiKeyRequest(t *testing.T, req *http.Request, keyID uuid.UUID) *http.Request {
	t.Helper()

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("keyID", keyID.String())
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}
