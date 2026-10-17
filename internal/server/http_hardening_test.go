package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

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
	for _, want := range []string{"frame-ancestors 'none'", "script-src 'self';", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "wss://hibou.example.com"} {
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
		handler.ServeHTTP(recorder, serviceUploadRequest(uuid.New(), uuid.New(), nil))
		done <- recorder.Code
	}()
	<-entered

	// Another org's token: only the global cap is in the way.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, serviceUploadRequest(uuid.New(), uuid.New(), nil))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("second upload = %d (Retry-After %q), want 429 with Retry-After", recorder.Code, recorder.Header().Get("Retry-After"))
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

// The server-wide write timeout must not cut a download, and must still cut
// everything else, the websocket handshake included: that one lifts its
// deadlines in ws.HTTPHandler once the session is validated, never here
// before authentication.
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
	if body, err := get(websocketPath); err == nil && body == "late" {
		t.Fatal("websocket path: the write timeout must apply until the handler validated the session")
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

// A websocket handshake carries no body: one that does could trickle it to
// hold a connection open, and is refused before any handler runs.
func TestConnectionDeadlineMiddlewareRefusesWebsocketBody(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{})
	handler := srv.connectionDeadlineMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	serve := func(request *http.Request) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	if got := serve(httptest.NewRequest(http.MethodGet, websocketPath, nil)); got != http.StatusSwitchingProtocols {
		t.Fatalf("bodiless handshake = %d, want passed through", got)
	}
	if got := serve(httptest.NewRequest(http.MethodGet, websocketPath, strings.NewReader("x"))); got != http.StatusBadRequest {
		t.Fatalf("handshake with Content-Length = %d, want 400", got)
	}
	chunked := httptest.NewRequest(http.MethodGet, websocketPath, io.MultiReader(strings.NewReader("x")))
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	if got := serve(chunked); got != http.StatusBadRequest {
		t.Fatalf("chunked handshake = %d, want 400", got)
	}
}

// Route classes are decided on the escaped path chi routes on: an encoded
// slash or letter cannot borrow the limits of another route.
func TestHardeningClassifiesEscapedPath(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{MaxUploadSize: 4 << 20})
	var hasDeadline atomic.Bool
	timeouts := srv.requestTimeoutMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Deadline()
		hasDeadline.Store(ok)
	}))
	encodedDownload := "/api/v1/orgs/github/acme%2Fsnapshots%2Fx%2Ffiles/y"
	timeouts.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, encodedDownload, nil))
	if !hasDeadline.Load() {
		t.Error("encoded slashes made an ordinary route look like a long-running download")
	}

	limited := srv.bodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	limited.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/%75pload", bytes.NewReader(make([]byte, 2<<20))))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("encoded /upload = %d, want the default 1 MB cap (chi does not route it to /upload)", recorder.Code)
	}
}

// IPv6 clients share a bucket per /64 (every address of which they can use);
// IPv4 clients are keyed per address.
func TestRateLimitIPKey(t *testing.T) {
	t.Parallel()

	for host, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"not-an-ip":            "not-an-ip",
	} {
		if got := rateLimitIPKey(host); got != want {
			t.Errorf("rateLimitIPKey(%q) = %q, want %q", host, got, want)
		}
	}
	a := httptest.NewRequest(http.MethodGet, "/", nil)
	a.RemoteAddr = "[2001:db8::1]:1234"
	b := httptest.NewRequest(http.MethodGet, "/", nil)
	b.RemoteAddr = "[2001:db8::ffff:2]:1234"
	if ipRateKey(a) != ipRateKey(b) || principalRateKey(a) != ipRateKey(a) {
		t.Errorf("same /64 keyed apart: %q vs %q", ipRateKey(a), ipRateKey(b))
	}
}

// The bucket map is capped: past it, new keys share one overflow bucket, so
// rotating addresses neither grows memory nor buys fresh bursts. Idle
// buckets are swept.
func TestIPRateLimiterCapsKeys(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := newIPRateLimiterWithCap(ctx, 1, 1, rateLimiterShards)
	for i := 0; i < 10*rateLimiterShards; i++ {
		limiter.getLimiter("ip:" + strconv.Itoa(i))
	}
	if got := limiter.size(); got > rateLimiterShards {
		t.Fatalf("limiter holds %d keys, want at most %d", got, rateLimiterShards)
	}
	overflowed := 0
	for i := 10 * rateLimiterShards; i < 20*rateLimiterShards; i++ {
		if limiter.getLimiter("ip:"+strconv.Itoa(i)) == limiter.overflow {
			overflowed++
		}
	}
	if overflowed != 10*rateLimiterShards {
		t.Fatalf("%d of %d new keys got the overflow bucket, want all", overflowed, 10*rateLimiterShards)
	}
	limiter.sweep(time.Now().Add(rateLimitIdleTTL + time.Second))
	if got := limiter.size(); got != 0 {
		t.Fatalf("idle buckets left after sweep: %d", got)
	}
}

// http.forwarded_hops=0 ignores X-Forwarded-For: a client that reaches hibou
// directly cannot choose its IP.
func TestForwardedHopsZeroIgnoresXFF(t *testing.T) {
	t.Parallel()

	for hops, want := range map[int]string{0: "198.51.100.1", 1: "203.0.113.9", 2: "192.0.2.4"} {
		router := chi.NewRouter()
		configureRouterWithHops(router, zerolog.New(io.Discard), hops)
		router.Get("/ip", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, requestClientIP(r))
		})
		request := httptest.NewRequest(http.MethodGet, "/ip", nil)
		request.RemoteAddr = "198.51.100.1:5555"
		request.Header.Set("X-Forwarded-For", "192.0.2.4, 203.0.113.9")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if got := recorder.Body.String(); got != want {
			t.Errorf("forwarded_hops=%d: client IP %q, want %q", hops, got, want)
		}
	}
}

// Random bearer tokens are throttled per client IP before the token lookup;
// requests that authenticate are not charged, and requests without a token
// (browsers behind the same NAT) are never held back by the gate.
func TestAuthFailureGateThrottlesBadTokensPerIP(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := newHardeningTestServer(config.Config{})
	srv.rateLimiters.authFailure = newIPRateLimiter(ctx, 0.01, 3)
	var lookups atomic.Int32
	// Stands in for SessionAuth: "good" resolves to a user.
	fakeAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lookups.Add(1)
			if r.Header.Get("Authorization") == "Bearer good" {
				r = r.WithContext(auth.WithUser(r.Context(), &store.User{ID: uuid.New()}))
			}
			next.ServeHTTP(w, r)
		})
	}
	handler := srv.authFailureGate(fakeAuth(srv.authFailureCount(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))
	call := func(remote, token string) int {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		request.RemoteAddr = remote
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	for i := 0; i < 5; i++ {
		if got := call("203.0.113.7:1", "good"); got != http.StatusNoContent {
			t.Fatalf("valid token %d = %d, want 204 (successes are not charged)", i, got)
		}
	}
	for i := 0; i < 3; i++ {
		call("203.0.113.7:1", "random"+strconv.Itoa(i))
	}
	before := lookups.Load()
	if got := call("203.0.113.7:1", "random-again"); got != http.StatusTooManyRequests {
		t.Fatalf("bad token past the budget = %d, want 429", got)
	}
	if lookups.Load() != before {
		t.Fatal("a throttled token still reached the lookup")
	}
	if got := call("203.0.113.7:1", ""); got != http.StatusNoContent {
		t.Fatalf("request without a token from the same IP = %d, want passed through", got)
	}
	if got := call("198.51.100.2:1", "random"); got != http.StatusNoContent {
		t.Fatalf("other IP = %d, want its own budget", got)
	}
}

// Uploads must announce their size; the read budget follows it.
func TestUploadRequiresContentLengthAndBudgetsByIt(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{})
	srv.uploadSlots = make(chan struct{}, 3)
	handler := srv.uploadConcurrencyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	request := serviceUploadRequest(uuid.New(), uuid.New(), io.MultiReader(strings.NewReader("{}")))
	request.ContentLength = -1
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusLengthRequired {
		t.Fatalf("upload without Content-Length = %d, want 411", recorder.Code)
	}

	ceiling := 15 * time.Minute
	for length, want := range map[int64]time.Duration{
		0:                 time.Minute,
		1 << 20:           time.Minute,
		64 << 10 * 120:    2 * time.Minute,
		64 << 10 * 100000: ceiling,
	} {
		if got := uploadReadBudget(length, ceiling); got != want {
			t.Errorf("uploadReadBudget(%d) = %s, want %s", length, got, want)
		}
	}
	if got := uploadReadBudget(10<<20, 30*time.Second); got != 30*time.Second {
		t.Errorf("budget above a short upload_read_timeout = %s, want the timeout", got)
	}
}

// One principal or org never holds every global slot.
func TestUploadKeyLimitLeavesASlot(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{})
	for slots, want := range map[int]int{1: 5, 2: 1, 3: 2, 6: 5, 10: 5} {
		srv.uploadSlots = make(chan struct{}, slots)
		if got := srv.uploadKeyLimit(5); got != want {
			t.Errorf("%d slots: limit 5 -> %d, want %d", slots, got, want)
		}
	}
}

// Once the keyed buckets are full, an unseen address shares its /48 (IPv6)
// or /24 (IPv4) bucket, so a client rotating through a large IPv6 range
// exhausts its own range, not every newcomer's. The failed-token gate never
// refuses on the global overflow bucket, which unrelated clients share.
func TestRateLimiterOverflowIsCoarseAndNeverLocksEveryoneOut(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := newIPRateLimiterWithCap(ctx, 0.001, 1, rateLimiterShards)
	// Fill the keyed buckets with one attacker's /64s inside 2001:db8:1::/48.
	for i := 0; i < 10*rateLimiterShards; i++ {
		limiter.getLimiter("ip:" + rateLimitIPKey("2001:db8:1:"+strconv.FormatInt(int64(i), 16)+"::1"))
	}
	attacker, global := limiter.limiterFor("ip:" + rateLimitIPKey("2001:db8:1:ffff::1"))
	if global {
		t.Fatal("a full table sent an address to the global bucket before its /48")
	}
	attacker.Allow() // the attacker's range spends its token
	if !authFailuresExhausted(limiter, "ip:"+rateLimitIPKey("2001:db8:1:fffe::1")) {
		t.Error("the attacker's /48 is not throttled")
	}
	if authFailuresExhausted(limiter, "ip:"+rateLimitIPKey("2001:db8:2:1::1")) {
		t.Error("another /48 is throttled by the attacker's failures")
	}
	if authFailuresExhausted(limiter, "ip:"+rateLimitIPKey("198.51.100.7")) {
		t.Error("an IPv4 client is throttled by an IPv6 attacker")
	}

	// Even with the coarse table full, the shared global bucket never
	// refuses a token on its own.
	full := newIPRateLimiterWithCap(ctx, 0.001, 1, rateLimiterShards)
	for i := 0; i < 10*rateLimiterShards; i++ {
		full.getLimiter("ip:" + strconv.Itoa(i))
	}
	full.coarse.mu.Lock()
	for i := len(full.coarse.entries); i < maxCoarseRateLimitKeys; i++ {
		full.coarse.entries["net:filler-"+strconv.Itoa(i)] = &limiterEntry{limiter: full.overflow, lastSeen: time.Now()}
	}
	full.coarse.mu.Unlock()
	full.overflow.Allow()
	if bucket, global := full.limiterFor("ip:" + rateLimitIPKey("2001:db8:9::1")); !global || bucket != full.overflow {
		t.Fatal("expected the global bucket once both tables are full")
	}
	if authFailuresExhausted(full, "ip:"+rateLimitIPKey("2001:db8:9::1")) {
		t.Error("the failed-token gate refused on the shared global bucket")
	}
}
