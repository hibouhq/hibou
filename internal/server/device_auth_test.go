package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
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
	req.RemoteAddr = "[" + deviceTestIP(t) + "]:4242"
	return req
}

// deviceTestIPs gives each test its own requester address for the whole run.
// Pending device logins persist in the shared test database and are capped
// per IP, so a fixed address fills up across runs and tests start failing
// with slow_down.
var deviceTestIPs sync.Map

func deviceTestIP(t *testing.T) string {
	t.Helper()
	if ip, ok := deviceTestIPs.Load(t.Name()); ok {
		return ip.(string)
	}
	id := uuid.New()
	ip := fmt.Sprintf("2001:db8:%x:%x::1", binary.BigEndian.Uint16(id[0:2]), binary.BigEndian.Uint16(id[2:4]))
	actual, _ := deviceTestIPs.LoadOrStore(t.Name(), ip)
	return actual.(string)
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
	if view.Data.ClientName != "devbox[31m" || view.Data.RequesterIP != deviceTestIP(t) || view.Data.RequestedPreset != "cli" {
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

func TestDevicePresetWithin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		approved, requested apitoken.Preset
		want                bool
	}{
		{apitoken.PresetReadOnly, apitoken.PresetReadOnly, true},
		{apitoken.PresetReadOnly, apitoken.PresetCLI, true},
		{apitoken.PresetCLI, apitoken.PresetCLI, true},
		{apitoken.PresetCLI, apitoken.PresetReadOnly, false},
		{apitoken.PresetTriage, apitoken.PresetTriage, true},
		{apitoken.PresetReadOnly, apitoken.PresetTriage, true},
		{apitoken.PresetTriage, apitoken.PresetReadOnly, false},
		// cli uploads, triage changes finding state: neither narrows to the other.
		{apitoken.PresetCLI, apitoken.PresetTriage, false},
		{apitoken.PresetTriage, apitoken.PresetCLI, false},
		{"admin", apitoken.PresetCLI, false},
		{apitoken.PresetReadOnly, "", false},
	}
	for _, tc := range cases {
		if got := devicePresetWithin(tc.approved, tc.requested); got != tc.want {
			t.Errorf("devicePresetWithin(%q, %q) = %v, want %v", tc.approved, tc.requested, got, tc.want)
		}
	}
}

func TestDeviceApproveCannotRaiseRequestedPreset(t *testing.T) {
	t.Parallel()
	srv, _, admin, _ := newDeviceTestServer(t)

	// IDE clients default to read-only.
	auth := startDeviceLogin(t, srv, devicelogin.ClientVSCode, "")

	lookup := httptest.NewRecorder()
	srv.handleDeviceLookup(lookup, asUser(deviceJSON(t, http.MethodGet, "/api/v1/auth/device?user_code="+url.QueryEscape(auth.UserCode), nil), admin))
	if lookup.Code != http.StatusOK {
		t.Fatalf("lookup: %d %s", lookup.Code, lookup.Body.String())
	}
	var view struct {
		Data deviceRequestView `json:"data"`
	}
	if err := json.Unmarshal(lookup.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Data.RequestedPreset != string(apitoken.PresetReadOnly) || len(view.Data.Presets) != 1 || view.Data.Presets[0].Key != string(apitoken.PresetReadOnly) {
		t.Fatalf("IDE lookup offers %+v (requested %q), want read-only only", view.Data.Presets, view.Data.RequestedPreset)
	}

	raise := httptest.NewRecorder()
	srv.handleDeviceApprove(raise, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: auth.UserCode, Preset: "cli"}), admin))
	if raise.Code != http.StatusBadRequest {
		t.Fatalf("approving cli for a read-only request = %d, want 400", raise.Code)
	}

	// A CLI request can be lowered to read-only.
	cli := startDeviceLogin(t, srv, devicelogin.ClientCLI, "")
	lower := httptest.NewRecorder()
	srv.handleDeviceApprove(lower, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: cli.UserCode, Preset: "read-only"}), admin))
	if lower.Code != http.StatusOK {
		t.Fatalf("lowering cli to read-only = %d %s", lower.Code, lower.Body.String())
	}
	if code, body := pollDevice(t, srv, cli.DeviceCode, devicelogin.ClientCLI); code != http.StatusOK || body["preset"] != "read-only" {
		t.Fatalf("poll after lowered approval = %d %v", code, body)
	}
}

func TestDeviceIDETriagePresetIsOptIn(t *testing.T) {
	t.Parallel()
	srv, _, admin, _ := newDeviceTestServer(t)

	// The IDEs ask for triage; the page offers it next to read-only.
	auth := startDeviceLogin(t, srv, devicelogin.ClientVSCode, "triage")
	lookup := httptest.NewRecorder()
	srv.handleDeviceLookup(lookup, asUser(deviceJSON(t, http.MethodGet, "/api/v1/auth/device?user_code="+url.QueryEscape(auth.UserCode), nil), admin))
	if lookup.Code != http.StatusOK {
		t.Fatalf("lookup: %d %s", lookup.Code, lookup.Body.String())
	}
	var view struct {
		Data deviceRequestView `json:"data"`
	}
	if err := json.Unmarshal(lookup.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	var offered []string
	for _, p := range view.Data.Presets {
		offered = append(offered, p.Key)
	}
	if strings.Join(offered, ",") != "triage,read-only" {
		t.Fatalf("triage request offers %v, want [triage read-only]", offered)
	}

	raise := httptest.NewRecorder()
	srv.handleDeviceApprove(raise, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: auth.UserCode, Preset: "cli"}), admin))
	if raise.Code != http.StatusBadRequest {
		t.Fatalf("approving cli for a triage request = %d, want 400", raise.Code)
	}

	approve := httptest.NewRecorder()
	srv.handleDeviceApprove(approve, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: auth.UserCode, Preset: "triage"}), admin))
	if approve.Code != http.StatusOK {
		t.Fatalf("approve triage: %d %s", approve.Code, approve.Body.String())
	}
	code, body := pollDevice(t, srv, auth.DeviceCode, devicelogin.ClientVSCode)
	if code != http.StatusOK || body["preset"] != "triage" {
		t.Fatalf("poll = %d %v, want a triage token", code, body)
	}
	key, err := srv.queries.GetAPIKeyByHash(context.Background(), store.HashAPIKey(body["access_token"].(string)))
	if err != nil || key == nil {
		t.Fatalf("minted key not found: %v", err)
	}
	var scope apitoken.Scope
	if err := json.Unmarshal(key.Scopes, &scope); err != nil {
		t.Fatal(err)
	}
	if scope.Permissions[apitoken.CapTriage] != apitoken.AccessWrite || scope.Permissions[apitoken.CapUploads] != apitoken.AccessRead {
		t.Fatalf("triage token permissions = %v, want triage:write and nothing else above read", scope.Permissions)
	}
}

func TestDeviceTokenRechecksKeyQuotaAtMint(t *testing.T) {
	t.Parallel()
	srv, _, admin, _ := newDeviceTestServer(t)
	ctx := context.Background()

	scope, _ := apitoken.MembershipScope(admin.ID.String(), apitoken.PresetReadOnly)
	scopes, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := srv.queries.CountAPIKeysCreatedByUser(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := existing; i < maxAPIKeysPerUser-1; i++ {
		if _, _, err := mintUserAPIKey(ctx, srv.queries, admin.ID, "filler", "", scopes, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Both approvals pass the approval-time check (one slot left)...
	first := startDeviceLogin(t, srv, devicelogin.ClientCLI, "")
	second := startDeviceLogin(t, srv, devicelogin.ClientCLI, "")
	for _, a := range []devicelogin.Authorization{first, second} {
		rec := httptest.NewRecorder()
		srv.handleDeviceApprove(rec, asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: a.UserCode, Preset: "cli"}), admin))
		if rec.Code != http.StatusOK {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
		}
	}

	// ...but only one may mint.
	if code, body := pollDevice(t, srv, first.DeviceCode, devicelogin.ClientCLI); code != http.StatusOK {
		t.Fatalf("first poll = %d %v", code, body)
	}
	if code, body := pollDevice(t, srv, second.DeviceCode, devicelogin.ClientCLI); code != http.StatusBadRequest || body["error"] != devicelogin.ErrCodeAccessDenied {
		t.Fatalf("poll over the key cap = %d %v, want access_denied", code, body)
	}
	if code, body := pollDevice(t, srv, second.DeviceCode, devicelogin.ClientCLI); body["error"] != devicelogin.ErrCodeExpired {
		t.Fatalf("poll after quota refusal = %d %v, want expired_token (request spent)", code, body)
	}
	count, err := srv.queries.CountAPIKeysCreatedByUser(ctx, admin.ID)
	if err != nil || count != maxAPIKeysPerUser {
		t.Fatalf("keys = %d (%v), want %d", count, err, maxAPIKeysPerUser)
	}
}

func TestDeviceCodeLimiterLocksOutPerIPAndGlobally(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	l := newDeviceCodeLimiter(3, 5, time.Minute)
	l.now = func() time.Time { return now }

	for range 3 {
		if _, locked := l.blocked("10.0.0.1"); locked {
			t.Fatal("locked before the per-IP cap")
		}
		l.fail("10.0.0.1")
	}
	if retry, locked := l.blocked("10.0.0.1"); !locked || retry <= 0 || retry > time.Minute {
		t.Fatalf("after 3 failures: locked=%v retry=%v, want locked", locked, retry)
	}
	if _, locked := l.blocked("10.0.0.2"); locked {
		t.Fatal("another IP is locked before the global cap")
	}

	l.fail("10.0.0.2")
	l.fail("10.0.0.3")
	if _, locked := l.blocked("10.0.0.4"); !locked {
		t.Fatal("global cap reached but a fresh IP is not locked")
	}

	now = now.Add(time.Minute)
	if _, locked := l.blocked("10.0.0.1"); locked {
		t.Fatal("lockout outlived its window")
	}
}

func TestDeviceLookupLockoutAfterFailedCodes(t *testing.T) {
	t.Parallel()
	srv, _, admin, _ := newDeviceTestServer(t)
	auth := startDeviceLogin(t, srv, devicelogin.ClientCLI, "")

	fromIP := func(req *http.Request) *http.Request {
		req.RemoteAddr = "198.51.100.77:5555" // own IP: the guard is process-wide
		return req
	}
	for i := range deviceCodeFailuresPerIP {
		rec := httptest.NewRecorder()
		srv.handleDeviceLookup(rec, fromIP(asUser(deviceJSON(t, http.MethodGet, "/api/v1/auth/device?user_code=ZZZZ-ZZZ"+string(rune('A'+i%20)), nil), admin)))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("guess %d = %d, want 404", i, rec.Code)
		}
	}
	// Locked out: even the right code, and approve/deny, get 429.
	lookup := httptest.NewRecorder()
	srv.handleDeviceLookup(lookup, fromIP(asUser(deviceJSON(t, http.MethodGet, "/api/v1/auth/device?user_code="+url.QueryEscape(auth.UserCode), nil), admin)))
	if lookup.Code != http.StatusTooManyRequests || lookup.Header().Get("Retry-After") == "" {
		t.Fatalf("lookup while locked = %d (Retry-After %q), want 429", lookup.Code, lookup.Header().Get("Retry-After"))
	}
	approve := httptest.NewRecorder()
	srv.handleDeviceApprove(approve, fromIP(asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{UserCode: auth.UserCode, Preset: "cli"}), admin)))
	if approve.Code != http.StatusTooManyRequests {
		t.Fatalf("approve while locked = %d, want 429", approve.Code)
	}
	deny := httptest.NewRecorder()
	srv.handleDeviceDeny(deny, fromIP(asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/deny", deviceDecisionRequest{UserCode: auth.UserCode}), admin)))
	if deny.Code != http.StatusTooManyRequests {
		t.Fatalf("deny while locked = %d, want 429", deny.Code)
	}

	// Other addresses are unaffected.
	ok := httptest.NewRecorder()
	srv.handleDeviceLookup(ok, asUser(deviceJSON(t, http.MethodGet, "/api/v1/auth/device?user_code="+url.QueryEscape(auth.UserCode), nil), admin))
	if ok.Code != http.StatusOK {
		t.Fatalf("lookup from another IP = %d, want 200", ok.Code)
	}
}

// Approving mints a token valid for up to a year, so it needs a recent
// sign-in: a session cookie older than deviceApproveMaxSessionAge (or none) is
// refused, a fresh one is accepted.
func TestDeviceApproveNeedsRecentSession(t *testing.T) {
	srv, _, admin, _ := newDeviceTestServer(t)
	srv.authMgr = internalauth.New(internalauth.Config{SessionSecret: "0123456789abcdef0123456789abcdef"}, nil)
	authz := startDeviceLogin(t, srv, devicelogin.ClientCLI, "cli")

	approve := func(withCookie bool) *httptest.ResponseRecorder {
		req := asUser(deviceJSON(t, http.MethodPost, "/api/v1/auth/device/approve", deviceDecisionRequest{
			UserCode: authz.UserCode, Preset: "cli",
		}), admin)
		if withCookie {
			issued := httptest.NewRecorder()
			srv.authMgr.SetSessionCookie(issued, admin)
			for _, cookie := range issued.Result().Cookies() {
				req.AddCookie(cookie)
			}
		}
		rec := httptest.NewRecorder()
		srv.handleDeviceApprove(rec, req)
		return rec
	}

	if rec := approve(false); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "sign in again") {
		t.Fatalf("approve without a verifiable session = %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := approve(true); rec.Code != http.StatusOK {
		t.Fatalf("approve with a fresh session = %d %s, want 200", rec.Code, rec.Body.String())
	}
}
