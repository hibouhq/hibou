package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func newWebhookTestServer(t *testing.T, development bool, webhookSecret string) (http.Handler, *int) {
	t.Helper()
	srv := &Server{
		cfg:             config.Config{Development: development},
		log:             zerolog.Nop(),
		forges:          map[string]forge.Provider{"github": forge.NewGitHub("id", "secret", webhookSecret)},
		webhookHandlers: make(map[string][]forgeEventHandler),
	}
	pushes := 0
	srv.registerWebhookHandler("push", func(context.Context, string, forge.WebhookEvent) error {
		pushes++
		return nil
	})
	router := chi.NewRouter()
	router.Post("/api/v1/webhooks/{provider}", srv.handleWebhook)
	return router, &pushes
}

func githubPushRequest(secret, delivery, before, after string) *http.Request {
	body := []byte(`{"ref":"refs/heads/main","before":"` + before + `","after":"` + after + `","repository":{"id":1,"name":"api","full_name":"acme/api","owner":{"login":"acme"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-GitHub-Delivery", delivery)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return req
}

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	sha0 = strings.Repeat("0", 40)
)

// §3.4: without a webhook secret, production refuses every delivery;
// development accepts it unverified.
func TestWebhookWithoutSecretFailsClosedOutsideDevelopment(t *testing.T) {
	t.Parallel()

	prod, prodPushes := newWebhookTestServer(t, false, "")
	recorder := httptest.NewRecorder()
	prod.ServeHTTP(recorder, githubPushRequest("", "d-1", sha0, shaA))
	if recorder.Code != http.StatusUnauthorized || *prodPushes != 0 {
		t.Fatalf("production without secret: status %d, pushes %d; want 401, 0", recorder.Code, *prodPushes)
	}

	dev, devPushes := newWebhookTestServer(t, true, "")
	recorder = httptest.NewRecorder()
	dev.ServeHTTP(recorder, githubPushRequest("", "d-1", sha0, shaA))
	if recorder.Code != http.StatusOK || *devPushes != 1 {
		t.Fatalf("development without secret: status %d, pushes %d; want 200, 1", recorder.Code, *devPushes)
	}
}

// §3.4: a verified delivery replayed (same delivery id, or same body under a
// new id) is acknowledged but not processed again.
func TestWebhookReplayIsNotReprocessed(t *testing.T) {
	t.Parallel()

	handler, pushes := newWebhookTestServer(t, false, "hook-secret")
	for _, delivery := range []string{"d-1", "d-1", "d-2"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, githubPushRequest("hook-secret", delivery, shaA, shaB))
		if recorder.Code != http.StatusOK {
			t.Fatalf("delivery %s: status %d", delivery, recorder.Code)
		}
	}
	if *pushes != 1 {
		t.Fatalf("pushes processed = %d, want 1", *pushes)
	}

	// A different event under a fresh id still goes through.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, githubPushRequest("hook-secret", "d-3", shaB, shaA))
	if recorder.Code != http.StatusOK || *pushes != 2 {
		t.Fatalf("new delivery: status %d, pushes %d", recorder.Code, *pushes)
	}
}

// §3.4: push SHAs reach git command lines; anything but an object id is refused.
func TestWebhookRejectsMalformedPushSHA(t *testing.T) {
	t.Parallel()

	handler, pushes := newWebhookTestServer(t, false, "hook-secret")
	for i, after := range []string{"--output=/tmp/x", "HEAD", strings.ToUpper(shaA), shaA[:39]} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, githubPushRequest("hook-secret", "bad-"+string(rune('a'+i)), shaA, after))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("after=%q: status %d, want 400", after, recorder.Code)
		}
	}
	if *pushes != 0 {
		t.Fatalf("malformed pushes processed: %d", *pushes)
	}
}

func TestWebhookDeliveryCacheIsBounded(t *testing.T) {
	t.Parallel()

	cache := newWebhookDeliveryCache(time.Hour, 3)
	now := time.Now()
	for i, key := range []string{"a", "b", "c", "d"} {
		if !cache.claim([]string{key}, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("fresh key %q refused", key)
		}
	}
	if len(cache.seen) > 3 {
		t.Fatalf("cache grew to %d keys, max 3", len(cache.seen))
	}
	if cache.claim([]string{"d"}, now.Add(5*time.Second)) {
		t.Fatal("recent key must be refused")
	}
	if !cache.claim([]string{"d"}, now.Add(2*time.Hour)) {
		t.Fatal("expired key must be accepted again")
	}
}

// A6: cookie-authenticated cross-site writes are refused.
func TestCSRFRequestAllowed(t *testing.T) {
	t.Parallel()

	const base = "https://hibou.example.com"
	cases := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		allowed bool
	}{
		{"safe method", http.MethodGet, "/api/v1/orgs", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"same origin", http.MethodPost, "/api/v1/orgs", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": base}, true},
		{"non-browser client", http.MethodPost, "/api/v1/orgs", nil, true},
		{"cross-site fetch", http.MethodPost, "/api/v1/orgs", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"sibling subdomain", http.MethodDelete, "/api/v1/orgs/x", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"foreign origin", http.MethodPost, "/api/v1/orgs", map[string]string{"Origin": "https://evil.example.net"}, false},
		{"http downgrade origin", http.MethodPost, "/api/v1/orgs", map[string]string{"Origin": "http://hibou.example.com"}, false},
		{"null origin", http.MethodPost, "/api/v1/orgs", map[string]string{"Origin": "null"}, false},
		{"bearer token", http.MethodPost, "/api/v1/upload", map[string]string{"Authorization": "Bearer hb_x", "Origin": "https://evil.example.net"}, true},
		{"webhook", http.MethodPost, "/api/v1/webhooks/github", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		if got := csrfRequestAllowed(req, base, false); got != tc.allowed {
			t.Errorf("%s: allowed = %v, want %v", tc.name, got, tc.allowed)
		}
	}

	// Without a base URL (development) the request host is the origin.
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8585/api/v1/orgs", nil)
	req.Header.Set("Origin", "http://localhost:8585")
	if !csrfRequestAllowed(req, "", false) {
		t.Fatal("same-host origin must pass without a base URL")
	}

	// Development behind the Vite proxy: Host is rewritten to the API port.
	proxied := httptest.NewRequest(http.MethodPost, "http://localhost:8585/api/v1/orgs", nil)
	proxied.Header.Set("Origin", "http://localhost:5173")
	if csrfRequestAllowed(proxied, "", false) {
		t.Fatal("a different origin must fail outside development")
	}
	if !csrfRequestAllowed(proxied, "", true) {
		t.Fatal("a loopback origin must pass in development")
	}
}

// §4.1: an org on a provider this instance does not serve is refused (it
// would skip the forge admin check entirely).
func TestHandleCreateOrgRejectsUnconfiguredProvider(t *testing.T) {
	t.Parallel()

	srv := &Server{
		forges: map[string]forge.Provider{"github": forge.NewGitHub("id", "secret", "hook")},
		log:    zerolog.Nop(),
	}
	user := &store.User{ID: uniqueUUID(t), Provider: "github", ProviderID: "1", Email: "u@example.com"}
	recorder := httptest.NewRecorder()
	srv.handleCreateOrg(recorder, newCreateOrgRequest(t, user, createOrgRequest{Name: "Squat", Slug: "squat", DisplayName: "Squat", Provider: "gitlab"}))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

// A10: a later (or removed) expiry extends the token; an earlier one does not.
func TestExpiryExtends(t *testing.T) {
	t.Parallel()

	now := time.Now()
	later := now.Add(24 * time.Hour)
	if !expiryExtends(&now, &later) || !expiryExtends(&now, nil) {
		t.Fatal("pushing out or removing the expiry must count as an extension")
	}
	if expiryExtends(&later, &now) || expiryExtends(&now, &now) || expiryExtends(nil, &now) {
		t.Fatal("shortening or keeping the expiry is not an extension")
	}
}
