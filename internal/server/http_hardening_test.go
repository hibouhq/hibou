package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/store"
)

func newHardeningTestServer(cfg config.Config) *Server {
	return &Server{cfg: cfg, limits: effectiveLimits(cfg.Limits)}
}

func TestBodyLimitMiddlewareCapsByRoute(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{MaxUploadSize: 4 << 20})
	handler := srv.bodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	post := func(path string, size int, chunked bool) int {
		var body io.Reader = bytes.NewReader(make([]byte, size))
		if chunked {
			// No Content-Length: the limit must hold while streaming too.
			body = io.MultiReader(body)
		}
		req := httptest.NewRequest(http.MethodPost, path, body)
		if chunked {
			req.ContentLength = -1
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}

	cases := []struct {
		path    string
		size    int
		chunked bool
		want    int
	}{
		{"/api/v1/orgs", 2 << 20, false, http.StatusRequestEntityTooLarge},
		{"/api/v1/orgs", 2 << 20, true, http.StatusRequestEntityTooLarge},
		{"/api/v1/orgs", 512 << 10, false, http.StatusNoContent},
		{"/api/v1/upload", 3 << 20, true, http.StatusNoContent},
		{"/api/v1/upload", 5 << 20, true, http.StatusRequestEntityTooLarge},
		{"/api/v1/tools/sbom/compare", 6 << 20, false, http.StatusNoContent},
		{"/api/v1/orgs/github/acme/repos/app/sbom/compare", 9 << 20, false, http.StatusRequestEntityTooLarge},
		{"/api/v1/webhooks/github/", 10 << 20, false, http.StatusNoContent},
	}
	for _, tc := range cases {
		if got := post(tc.path, tc.size, tc.chunked); got != tc.want {
			t.Errorf("POST %s (%d bytes, chunked=%v) = %d, want %d", tc.path, tc.size, tc.chunked, got, tc.want)
		}
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Parallel()

	serve := func(baseURL, path string) http.Header {
		srv := newHardeningTestServer(config.Config{BaseURL: baseURL})
		recorder := httptest.NewRecorder()
		srv.securityHeadersMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
			ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder.Header()
	}

	spa := serve("https://hibou.example.com", "/orgs/github/acme")
	csp := spa.Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "script-src 'self';", "object-src 'none'", "base-uri 'none'", "wss://hibou.example.com"} {
		if !strings.Contains(csp, want) {
			t.Errorf("SPA CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("SPA CSP must not allow inline script: %q", csp)
	}
	for header, want := range map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000",
	} {
		if got := spa.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	if got := serve("https://hibou.example.com", "/api/v1/orgs/github/acme/repos/app/snapshots/x/files/y").Get("Content-Security-Policy"); !strings.Contains(got, "sandbox") {
		t.Errorf("API/download CSP = %q, want a sandbox", got)
	}
	if got := serve("", "/api/v1/docs/index.html").Get("Content-Security-Policy"); !strings.Contains(got, "'unsafe-inline'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("swagger CSP = %q, want inline script allowed and framing denied", got)
	}
	if got := serve("http://localhost:8585", "/").Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS on a plain-http base URL = %q, want none", got)
	}
}

func TestRateLimitMiddlewareReturns429WithRetryAfter(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := newIPRateLimiter(ctx, 0.5, 2)
	handler := rateLimitMiddleware(limiter, principalRateKey)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(req *http.Request) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}
	alice := &store.User{ID: uuid.New()}
	aliceReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		return req.WithContext(auth.WithUser(req.Context(), alice))
	}
	for i := 0; i < 2; i++ {
		if got := call(aliceReq()).Code; got != http.StatusNoContent {
			t.Fatalf("request %d = %d, want 204 within the burst", i, got)
		}
	}
	limited := call(aliceReq())
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "2" {
		t.Fatalf("over burst = %d Retry-After %q, want 429 and 2", limited.Code, limited.Header().Get("Retry-After"))
	}
	// Another principal has its own bucket, even from the same address.
	keyReq := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	keyReq = keyReq.WithContext(auth.WithTokenAuth(keyReq.Context(), &auth.TokenAuth{KeyID: uuid.New()}))
	if got := call(keyReq).Code; got != http.StatusNoContent {
		t.Fatalf("other principal = %d, want 204", got)
	}
	// A nil limiter (rate limiting disabled) passes everything through.
	unlimited := rateLimitMiddleware(nil, ipRateKey)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < 5; i++ {
		recorder := httptest.NewRecorder()
		unlimited.ServeHTTP(recorder, aliceReq())
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("unlimited request %d = %d, want 204", i, recorder.Code)
		}
	}
}

func TestUploadConcurrencyMiddlewareRefusesWhenFull(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{Limits: config.LimitsConfig{Upload: config.UploadLimitsConfig{QueueWait: 20 * time.Millisecond}}})
	srv.uploadSlots = make(chan struct{}, 1)
	release := make(chan struct{})
	entered := make(chan struct{})
	handler := srv.uploadConcurrencyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))

	done := make(chan int)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, uploadPath, nil))
		done <- recorder.Code
	}()
	<-entered

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, uploadPath, nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("second upload = %d (Retry-After %q), want 503 with Retry-After", recorder.Code, recorder.Header().Get("Retry-After"))
	}
	close(release)
	if got := <-done; got != http.StatusAccepted {
		t.Fatalf("first upload = %d, want 202", got)
	}
}

func TestRequestTimeoutMiddlewareExemptsLongRoutes(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{})
	var hasDeadline atomic.Bool
	handler := srv.requestTimeoutMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Deadline()
		hasDeadline.Store(ok)
	}))
	for path, want := range map[string]bool{
		"/api/v1/orgs/github/acme/dashboard":                       true,
		"/api/v1/upload":                                           false,
		"/api/v1/secret-scan/check":                                false,
		"/api/v1/orgs/github/acme/components/scan":                 false,
		"/api/v1/orgs/github/acme/repos/app/snapshots/s/files.zip": false,
	} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		if hasDeadline.Load() != want {
			t.Errorf("%s: deadline = %v, want %v", path, hasDeadline.Load(), want)
		}
	}
}

// The server-wide write timeout must not cut a websocket or a download, and
// must still cut everything else.
func TestConnectionDeadlineMiddlewareLiftsWriteTimeout(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{})
	backend := httptest.NewUnstartedServer(srv.connectionDeadlineMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	})))
	backend.Config.WriteTimeout = 100 * time.Millisecond
	backend.Start()
	defer backend.Close()

	get := func(path string) (string, error) {
		resp, err := backend.Client().Get(backend.URL + path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	if body, err := get(websocketPath); err != nil || body != "late" {
		t.Fatalf("websocket path: body %q err %v, want the late write delivered", body, err)
	}
	if body, err := get("/api/v1/bin/linux/amd64"); err != nil || body != "late" {
		t.Fatalf("download path: body %q err %v, want the late write delivered", body, err)
	}
	if body, err := get("/api/v1/users/me"); err == nil && body == "late" {
		t.Fatal("ordinary path: the write timeout must still apply")
	}
}

func TestCooldownGate(t *testing.T) {
	t.Parallel()

	var gate cooldownGate
	org := uuid.New()
	now := time.Now()
	if ok, _ := gate.tryStart(org, time.Minute, now); !ok {
		t.Fatal("first run refused")
	}
	if ok, wait := gate.tryStart(org, time.Minute, now); ok || wait != 0 {
		t.Fatalf("concurrent run = %v/%v, want refused while running", ok, wait)
	}
	gate.finish(org, now)
	if ok, wait := gate.tryStart(org, time.Minute, now.Add(10*time.Second)); ok || wait != 50*time.Second {
		t.Fatalf("run in cooldown = %v/%v, want refused with 50s left", ok, wait)
	}
	if ok, _ := gate.tryStart(org, time.Minute, now.Add(2*time.Minute)); !ok {
		t.Fatal("run after the cooldown refused")
	}
	// A run that did nothing leaves no cooldown.
	gate.finish(org, time.Time{})
	if ok, _ := gate.tryStart(org, time.Minute, now.Add(2*time.Minute)); !ok {
		t.Fatal("run after a no-op run refused")
	}
}

func TestCoalescingRunnerCollapsesConcurrentRequests(t *testing.T) {
	t.Parallel()

	var runner coalescingRunner
	key := uuid.New()
	var runs atomic.Int32
	started := make(chan struct{}, 10)
	release := make(chan struct{})
	finished := make(chan struct{}, 10)
	job := func() {
		runs.Add(1)
		started <- struct{}{}
		<-release
		finished <- struct{}{}
	}
	runner.run(key, job)
	<-started
	for i := 0; i < 5; i++ {
		runner.run(key, job)
	}
	close(release)
	<-finished
	<-finished
	// Let the goroutine observe a clean state and exit.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runner.mu.Lock()
		_, running := runner.state[key]
		runner.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("runs = %d, want 2 (the first plus one coalesced follow-up)", got)
	}
}
