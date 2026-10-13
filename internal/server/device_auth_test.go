package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/devicelogin"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
)

func newDeviceTestServer(t *testing.T) (*Server, *store.Organization, *store.User, *store.User) {
	t.Helper()
	srv, org, admin, member := newDiscoveryTestServer(t)
	srv.cfg = config.Config{BaseURL: "https://hibou.example"}
	return srv, org, admin, member
}

func deviceJSON(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(payload))
	req.RemoteAddr = "203.0.113.7:4242"
	return req
}

func asUser(req *http.Request, user *store.User) *http.Request {
	return req.WithContext(internalauth.WithUser(req.Context(), user))
}

func startDeviceLogin(t *testing.T, srv *Server, clientID, preset string) devicelogin.Authorization {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleDeviceCode(rec, deviceJSON(t, http.MethodPost, "/api/v1/auth/device/code", devicelogin.CodeRequest{
		ClientID: clientID, ClientName: "devbox\x1b[31m", Scope: preset,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("device code: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("device code response must not be cacheable")
	}
	var auth devicelogin.Authorization
	if err := json.Unmarshal(rec.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	return auth
}

func pollDevice(t *testing.T, srv *Server, deviceCode, clientID string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleDeviceToken(rec, deviceJSON(t, http.MethodPost, "/api/v1/auth/device/token", devicelogin.TokenRequest{
		GrantType: devicelogin.GrantType, DeviceCode: deviceCode, ClientID: clientID,
	}))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestDeviceLoginApproveIssuesMembershipWideTokenOnce(t *testing.T) {
	t.Parallel()
	srv, org, admin, _ := newDeviceTestServer(t)
	ctx := context.Background()

	auth := startDeviceLogin(t, srv, devicelogin.ClientCLI, "")
	if auth.VerificationURI != "https://hibou.example/device" {
		t.Fatalf("verification_uri = %q", auth.VerificationURI)
	}
	if auth.VerificationURIComplete != auth.VerificationURI+"?user_code="+url.QueryEscape(auth.UserCode) {
		t.Fatalf("verification_uri_complete = %q", auth.VerificationURIComplete)
	}

	if code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientCLI); code != http.StatusBadRequest || body["error"] != devicelogin.ErrCodePending {
		t.Fatalf("first poll = %d %v, want authorization_pending", code, body)
	}
	if code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientCLI); body["error"] != devicelogin.ErrCodeSlowDown {
		t.Fatalf("immediate second poll = %d %v, want slow_down", code, body)
	}
	if code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientVSCode); body["error"] != devicelogin.ErrCodeInvalidClient {
		t.Fatalf("poll with another client_id = %d %v, want invalid_client", code, body)
	}

	// The approval page sees the request, typed in lower case without a dash.
	lookup := httptest.NewRecorder()
	typed := strings.ToLower(strings.ReplaceAll(auth.UserCode, "-", ""))
	srv.handleDeviceLookup(lookup, asUser(deviceJSON(t, http.MethodGet, "/api/v1/auth/device?user_code="+typed, nil), admin))
	if lookup.Code != http.StatusOK {
		t.Fatalf("lookup: %d %s", lookup.Code, lookup.Body.String())
	}
	var view struct {
		Data deviceRequestView `json:"data"`
	}
	if err := json.Unmarshal(lookup.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Data.ClientName != "devbox[31m" || view.Data.RequesterIP != "203.0.113.7" || view.Data.RequestedPreset != "cli" {
		t.Fatalf("lookup view = %+v", view.Data)
	}
	found := false
	for _, reach := range view.Data.Orgs {
		if reach.Slug == org.Slug && reach.Role == rbac.RoleAdmin && reach.Policy == rbac.LoginTokensAllow {
			found = true
		}
	}
	if !found {
		t.Fatalf("lookup orgs %+v do not list %s as admin/allow", view.Data.Orgs, org.Slug)
	}

	approve := httptest.NewRecorder()
	srv.handleDeviceApprove(approve, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{
		UserCode: auth.UserCode, Preset: "cli",
	}), admin))
	if approve.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", approve.Code, approve.Body.String())
	}

	code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientCLI)
	if code != http.StatusOK {
		t.Fatalf("poll after approval = %d %v", code, body)
	}
	rawToken, _ := body["access_token"].(string)
	if !strings.HasPrefix(rawToken, "hibou_pat_") || body["orgs"] != "memberships" || body["token_name"] != "CLI — devbox[31m" {
		t.Fatalf("token response = %v", body)
	}
	if code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientCLI); body["error"] != devicelogin.ErrCodeExpired {
		t.Fatalf("replayed device_code = %d %v, want expired_token", code, body)
	}

	apiKey, err := srv.queries.GetAPIKeyByHash(ctx, store.HashAPIKey(rawToken))
	if err != nil || apiKey == nil {
		t.Fatalf("minted key not found: %v", err)
	}
	scope, err := apiKey.Scope()
	if err != nil || !scope.MembershipWide() || scope.Org != "" {
		t.Fatalf("minted scope = %+v (%v)", scope, err)
	}

	// The token resolves to the user's role, bounded by the org policy.
	tokenReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		reqCtx := internalauth.WithUser(req.Context(), admin)
		reqCtx = internalauth.WithTokenAuth(reqCtx, internalauth.TokenAuthForAPIKey(apiKey))
		return req.WithContext(reqCtx)
	}
	for policy, want := range map[string]string{
		rbac.LoginTokensAllow:    rbac.RoleAdmin,
		rbac.LoginTokensReadOnly: rbac.RoleViewer,
		rbac.LoginTokensDeny:     "",
	} {
		if _, err := srv.queries.UpdateOrganizationSettings(ctx, org.ID, json.RawMessage(`{"login_tokens":"`+policy+`"}`)); err != nil {
			t.Fatal(err)
		}
		role, err := srv.principalOrgRole(tokenReq(), org.ID)
		if err != nil || role != want {
			t.Errorf("policy %s: role = %q (%v), want %q", policy, role, err, want)
		}
	}

	// Logout: the token revokes itself, and only itself.
	revoke := httptest.NewRecorder()
	srv.handleRevokeCurrentAPIKey(revoke, tokenReq())
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke current: %d %s", revoke.Code, revoke.Body.String())
	}
	if gone, _ := srv.queries.GetAPIKeyByHash(ctx, store.HashAPIKey(rawToken)); gone != nil {
		t.Fatal("revoked key still resolves")
	}
}

func TestDeviceLoginDenyAndSessionOnlyApproval(t *testing.T) {
	t.Parallel()
	srv, _, admin, _ := newDeviceTestServer(t)

	auth := startDeviceLogin(t, srv, devicelogin.ClientVSCode, "")

	// A token can never approve a device login.
	tokenApprove := httptest.NewRecorder()
	req := asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: auth.UserCode, Preset: "read-only"}), admin)
	req = req.WithContext(internalauth.WithTokenAuth(req.Context(), &internalauth.TokenAuth{Scoped: true}))
	srv.handleDeviceApprove(tokenApprove, req)
	if tokenApprove.Code != http.StatusForbidden {
		t.Fatalf("token approval = %d, want 403", tokenApprove.Code)
	}

	unknown := httptest.NewRecorder()
	srv.handleDeviceApprove(unknown, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: "BBBB-BBBB", Preset: "cli"}), admin))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown code approval = %d, want 404", unknown.Code)
	}

	deny := httptest.NewRecorder()
	srv.handleDeviceDeny(deny, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/deny", deviceDecisionRequest{UserCode: auth.UserCode}), admin))
	if deny.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", deny.Code, deny.Body.String())
	}
	if code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientVSCode); body["error"] != devicelogin.ErrCodeAccessDenied {
		t.Fatalf("poll after deny = %d %v, want access_denied", code, body)
	}

	// A decided code can no longer be looked up or approved.
	again := httptest.NewRecorder()
	srv.handleDeviceApprove(again, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: auth.UserCode, Preset: "cli"}), admin))
	if again.Code != http.StatusNotFound {
		t.Fatalf("approve after deny = %d, want 404", again.Code)
	}
}

func TestDeviceCodeRejectsUnknownClientAndPreset(t *testing.T) {
	t.Parallel()
	srv := &Server{cfg: config.Config{BaseURL: "https://hibou.example"}}
	for _, input := range []devicelogin.CodeRequest{
		{ClientID: "evil-client"},
		{ClientID: devicelogin.ClientCLI, Scope: "admin"},
	} {
		rec := httptest.NewRecorder()
		srv.handleDeviceCode(rec, deviceJSON(t, http.MethodPost, "/api/v1/auth/device/code", input))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%+v: status = %d, want 400", input, rec.Code)
		}
	}
}

func TestSanitizeClientNameAndTokenName(t *testing.T) {
	t.Parallel()
	if got := sanitizeClientName("  my\nlaptop\t "); got != "mylaptop" {
		t.Errorf("sanitizeClientName = %q", got)
	}
	if got := sanitizeClientName(strings.Repeat("é", 100)); len([]rune(got)) != deviceClientNameMax {
		t.Errorf("sanitizeClientName did not cap at %d runes: %d", deviceClientNameMax, len([]rune(got)))
	}
	if got := deviceTokenName(devicelogin.ClientIntelliJ, ""); got != "IDE — IntelliJ on unknown device" {
		t.Errorf("deviceTokenName = %q", got)
	}
}
