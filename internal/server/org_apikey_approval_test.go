package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

// ADR-022 amendment: a non-admin member's org token is created pending, fails
// authentication with a message that names the fix, and starts working the
// moment an org admin approves it. Rejection is just as explicit.
func TestOrgTokenApprovalFlow(t *testing.T) {
	t.Parallel()

	srv, org, admin, member := newDiscoveryTestServer(t)

	callOrgKeys := func(user *store.User, method, path string, body map[string]any, handler http.HandlerFunc, keyID string) *httptest.ResponseRecorder {
		t.Helper()
		var reader *bytes.Reader
		if body != nil {
			payload, _ := json.Marshal(body)
			reader = bytes.NewReader(payload)
		} else {
			reader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, reader)
		req = req.WithContext(internalauth.WithUser(req.Context(), user))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", org.Slug)
		if keyID != "" {
			routeCtx.URLParams.Add("keyID", keyID)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		return recorder
	}

	scope := map[string]any{
		"org":         org.Slug,
		"repos":       map[string]any{"mode": "all"},
		"permissions": map[string]any{"coverage": "read"},
	}
	rec := callOrgKeys(member, http.MethodPost, "/api-keys", map[string]any{
		"name":       "member-requested",
		"scopes":     scope,
		"expires_at": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}, srv.handleCreateOrgAPIKey, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("member create = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			Key    string       `json:"key"`
			APIKey store.APIKey `json:"api_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Data.APIKey.ApprovalStatus != store.APIKeyApprovalPending {
		t.Fatalf("member-created token approval = %q, want pending", created.Data.APIKey.ApprovalStatus)
	}

	// The pending token must fail authentication through the real middleware,
	// with the message that tells the caller what to do next.
	authenticate := func() *httptest.ResponseRecorder {
		t.Helper()
		reached := false
		handler := internalauth.SessionAuth(nil, srv.queries)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = internalauth.TokenAuthFromContext(r.Context()) != nil
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+created.Data.Key)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code == http.StatusOK && !reached {
			t.Fatalf("request passed middleware without token auth attached")
		}
		return recorder
	}

	if rec := authenticate(); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "pending approval") {
		t.Fatalf("pending token auth = %d %q, want 401 naming pending approval", rec.Code, rec.Body.String())
	}

	// Approval by an org admin flips the switch.
	keyID := created.Data.APIKey.ID.String()
	if rec := callOrgKeys(member, http.MethodPost, "/approve", nil, srv.handleApproveOrgAPIKey, keyID); rec.Code != http.StatusForbidden {
		t.Fatalf("member approve = %d, want 403", rec.Code)
	}
	rec = callOrgKeys(admin, http.MethodPost, "/approve", nil, srv.handleApproveOrgAPIKey, keyID)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin approve = %d: %s", rec.Code, rec.Body.String())
	}
	var approved struct {
		Data store.APIKey `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if approved.Data.ApprovalStatus != store.APIKeyApprovalApproved || approved.Data.ApprovedBy == nil || *approved.Data.ApprovedBy != admin.ID {
		t.Fatalf("approve result = %q approved_by=%v, want approved by admin", approved.Data.ApprovalStatus, approved.Data.ApprovedBy)
	}

	if rec := authenticate(); rec.Code != http.StatusOK {
		t.Fatalf("approved token auth = %d %q, want 200", rec.Code, rec.Body.String())
	}

	// The review decisions are on the audit trail with the admin as actor.
	logs, err := srv.queries.ListAuditLogsByResource(context.Background(), "api_key", keyID, 20, 0)
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	actions := make(map[string]bool, len(logs))
	for _, log := range logs {
		actions[log.Action] = true
	}
	if !actions["token.create"] || !actions["token.approve"] {
		t.Fatalf("audit actions = %v, want token.create and token.approve", actions)
	}

	// Rejection produces its own explicit authentication error.
	if rec := callOrgKeys(admin, http.MethodPost, "/reject", nil, srv.handleRejectOrgAPIKey, keyID); rec.Code != http.StatusOK {
		t.Fatalf("admin reject = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := authenticate(); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "rejected") {
		t.Fatalf("rejected token auth = %d %q, want 401 naming rejection", rec.Code, rec.Body.String())
	}

	// An admin-created org token needs no review.
	rec = callOrgKeys(admin, http.MethodPost, "/api-keys", map[string]any{
		"name":       "admin-minted",
		"scopes":     scope,
		"expires_at": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}, srv.handleCreateOrgAPIKey, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode admin create response: %v", err)
	}
	if created.Data.APIKey.ApprovalStatus != store.APIKeyApprovalApproved {
		t.Fatalf("admin-created token approval = %q, want approved", created.Data.APIKey.ApprovalStatus)
	}

	// The list is role-shaped: admins see the org's whole inventory, a member
	// sees only the keys they created (their own requests).
	listKeys := func(user *store.User) []store.APIKey {
		t.Helper()
		rec := callOrgKeys(user, http.MethodGet, "/api-keys", nil, srv.handleListOrgAPIKeys, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
		}
		var listed struct {
			Data []store.APIKey `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return listed.Data
	}
	if keys := listKeys(admin); len(keys) != 2 {
		t.Fatalf("admin list = %d keys, want 2", len(keys))
	}
	memberKeys := listKeys(member)
	if len(memberKeys) != 1 || memberKeys[0].Name != "member-requested" {
		t.Fatalf("member list = %+v, want only the member's own request", memberKeys)
	}
}

// A non-admin widening an approved token's scope drops it back to pending;
// narrowing does not.
func TestOrgTokenWideningResetsApproval(t *testing.T) {
	t.Parallel()

	srv, org, admin, member := newDiscoveryTestServer(t)

	call := func(user *store.User, body map[string]any, handler http.HandlerFunc, keyID string) *httptest.ResponseRecorder {
		t.Helper()
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPatch, "/api-keys", bytes.NewReader(payload))
		req = req.WithContext(internalauth.WithUser(req.Context(), user))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", org.Slug)
		if keyID != "" {
			routeCtx.URLParams.Add("keyID", keyID)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		return recorder
	}

	scopeWith := func(level string) map[string]any {
		return map[string]any{
			"org":         org.Slug,
			"repos":       map[string]any{"mode": "all"},
			"permissions": map[string]any{"coverage": level},
		}
	}

	rec := call(member, map[string]any{
		"name":       "widen-me",
		"scopes":     scopeWith("read"),
		"expires_at": time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}, srv.handleCreateOrgAPIKey, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			APIKey store.APIKey `json:"api_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	keyID := created.Data.APIKey.ID.String()

	if _, err := srv.queries.SetAPIKeyApprovalByOrg(context.Background(), created.Data.APIKey.ID, org.ID, store.APIKeyApprovalApproved, admin.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Another member cannot touch a key they did not create.
	outsider, err := srv.queries.CreateUser(context.Background(), uniqueName(t, "outsider")+"@example.com", "Outsider", "github", uniqueName(t, "outsider"))
	if err != nil {
		t.Fatalf("create outsider: %v", err)
	}
	if err := srv.queries.AddOrgMember(context.Background(), org.ID, outsider.ID, "developer"); err != nil {
		t.Fatalf("add outsider: %v", err)
	}
	if rec := call(outsider, map[string]any{"scopes": scopeWith("write")}, srv.handleUpdateOrgAPIKey, keyID); rec.Code != http.StatusForbidden {
		t.Fatalf("outsider edit = %d, want 403", rec.Code)
	}

	// The creator widening read→write re-triggers review.
	rec = call(member, map[string]any{"scopes": scopeWith("write")}, srv.handleUpdateOrgAPIKey, keyID)
	if rec.Code != http.StatusOK {
		t.Fatalf("widen = %d: %s", rec.Code, rec.Body.String())
	}
	var updated struct {
		Data store.APIKey `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode widen: %v", err)
	}
	if updated.Data.ApprovalStatus != store.APIKeyApprovalPending {
		t.Fatalf("after widen approval = %q, want pending", updated.Data.ApprovalStatus)
	}

	// Re-approve, then narrow write→read: no review needed.
	if _, err := srv.queries.SetAPIKeyApprovalByOrg(context.Background(), created.Data.APIKey.ID, org.ID, store.APIKeyApprovalApproved, admin.ID); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
	rec = call(member, map[string]any{"scopes": scopeWith("read")}, srv.handleUpdateOrgAPIKey, keyID)
	if rec.Code != http.StatusOK {
		t.Fatalf("narrow = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode narrow: %v", err)
	}
	if updated.Data.ApprovalStatus != store.APIKeyApprovalApproved {
		t.Fatalf("after narrow approval = %q, want approved (narrowing needs no review)", updated.Data.ApprovalStatus)
	}

	// An admin widening the same token stays approved — their approval is
	// implicit in the edit.
	rec = call(admin, map[string]any{"scopes": scopeWith("write")}, srv.handleUpdateOrgAPIKey, keyID)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin widen = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode admin widen: %v", err)
	}
	if updated.Data.ApprovalStatus != store.APIKeyApprovalApproved {
		t.Fatalf("after admin widen approval = %q, want approved", updated.Data.ApprovalStatus)
	}
}
