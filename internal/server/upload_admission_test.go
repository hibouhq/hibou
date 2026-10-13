package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ws"
)

// serviceUploadRequest is an upload by an org-owned token allowed to upload.
func serviceUploadRequest(keyID, orgID uuid.UUID, body io.Reader) *http.Request {
	return serviceUploadRequestWithScope(keyID, orgID, body, apitoken.Scope{
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapUploads: apitoken.AccessWrite},
	})
}

func serviceUploadRequestWithScope(keyID, orgID uuid.UUID, body io.Reader, scope apitoken.Scope) *http.Request {
	request := httptest.NewRequest(http.MethodPost, uploadPath, body)
	return request.WithContext(auth.WithTokenAuth(request.Context(), &auth.TokenAuth{
		KeyID:     keyID,
		OwnerType: "org",
		OwnerID:   orgID,
		Scope:     scope,
		Scoped:    true,
	}))
}

// The global slot is only queued for by a principal able to upload: an
// anonymous caller or a token without uploads:write is refused up front.
func TestUploadConcurrencyMiddlewareAdmitsBeforeQueueing(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{Limits: config.LimitsConfig{Upload: config.UploadLimitsConfig{QueueWait: 20 * time.Millisecond}}})
	// No free slot: anything admitted would wait and get 503.
	srv.uploadSlots = make(chan struct{})
	handler := srv.uploadConcurrencyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodPost, uploadPath, nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous upload = %d, want 401", anonymous.Code)
	}

	readOnly := httptest.NewRecorder()
	handler.ServeHTTP(readOnly, serviceUploadRequestWithScope(uuid.New(), uuid.New(), nil, apitoken.Scope{
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapUploads: apitoken.AccessRead},
	}))
	if readOnly.Code != http.StatusForbidden {
		t.Fatalf("read-only token upload = %d, want 403", readOnly.Code)
	}

	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, serviceUploadRequest(uuid.New(), uuid.New(), nil))
	if allowed.Code != http.StatusServiceUnavailable {
		t.Fatalf("admitted upload with no slot = %d, want 503", allowed.Code)
	}
}

// One org cannot hold every global slot: its tokens share
// upload.max_concurrent_per_org, and one token is capped on its own too.
func TestUploadConcurrencyMiddlewareCapsPerPrincipalAndOrg(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{Limits: config.LimitsConfig{Upload: config.UploadLimitsConfig{
		QueueWait:                 20 * time.Millisecond,
		MaxConcurrentPerPrincipal: 1,
		MaxConcurrentPerOrg:       2,
	}}})
	srv.uploadSlots = make(chan struct{}, 10)
	release := make(chan struct{})
	entered := make(chan struct{}, 10)
	handler := srv.uploadConcurrencyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))
	serve := func(request *http.Request) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	org, keyA, keyB := uuid.New(), uuid.New(), uuid.New()
	held := make(chan int, 2)
	go func() { held <- serve(serviceUploadRequest(keyA, org, nil)) }()
	<-entered

	if got := serve(serviceUploadRequest(keyA, org, nil)); got != http.StatusServiceUnavailable {
		t.Fatalf("second upload by the same token = %d, want 503", got)
	}
	go func() { held <- serve(serviceUploadRequest(keyB, org, nil)) }()
	<-entered
	if got := serve(serviceUploadRequest(uuid.New(), org, nil)); got != http.StatusServiceUnavailable {
		t.Fatalf("third upload for the same org = %d, want 503", got)
	}

	// Another tenant still gets through.
	otherDone := make(chan int, 1)
	go func() { otherDone <- serve(serviceUploadRequest(uuid.New(), uuid.New(), nil)) }()
	<-entered
	close(release)
	if got := <-otherDone; got != http.StatusAccepted {
		t.Fatalf("other org upload = %d, want 202", got)
	}
	for range 2 {
		if got := <-held; got != http.StatusAccepted {
			t.Fatalf("held upload = %d, want 202", got)
		}
	}
	// Released keys are freed.
	srv.uploadInFlight.mu.Lock()
	leftover := len(srv.uploadInFlight.counts)
	srv.uploadInFlight.mu.Unlock()
	if leftover != 0 {
		t.Fatalf("in-flight counters left behind: %d", leftover)
	}
}

// A queued upload takes the per-principal slot as soon as it is released.
func TestKeyedInFlightWaitsForRelease(t *testing.T) {
	t.Parallel()

	var limiter keyedInFlight
	keys := []inFlightKey{{key: "user:a", limit: 1}}
	if ok, _ := limiter.acquire(context.Background(), nil, keys); !ok {
		t.Fatal("first acquire failed")
	}
	got := make(chan bool, 1)
	go func() {
		ok, _ := limiter.acquire(context.Background(), time.After(5*time.Second), keys)
		got <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	limiter.release(keys)
	if !<-got {
		t.Fatal("waiting acquire did not get the released slot")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, cancelled := limiter.acquire(ctx, nil, keys); ok || !cancelled {
		t.Fatalf("acquire on a cancelled context = %v/%v, want refused and cancelled", ok, cancelled)
	}
}

// A body that stalls once it holds a slot is cut off after the throughput
// window rather than holding the slot for http.upload_read_timeout; a body
// that keeps up is untouched, and so is a handler busy after reading.
func TestUploadThroughputGuardCutsStalledBodies(t *testing.T) {
	t.Parallel()

	srv := newHardeningTestServer(config.Config{Limits: config.LimitsConfig{Upload: config.UploadLimitsConfig{
		MinThroughputBytes:  1024,
		MinThroughputWindow: 100 * time.Millisecond,
	}}})
	srv.uploadSlots = make(chan struct{}, 1)
	readErr := make(chan error, 1)
	handler := srv.uploadConcurrencyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			// Processing after the body is read must not be cut.
			time.Sleep(300 * time.Millisecond)
		}
		readErr <- err
		w.WriteHeader(http.StatusAccepted)
	}))
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := auth.WithTokenAuth(r.Context(), &auth.TokenAuth{
			KeyID: uuid.New(), OwnerType: "org", OwnerID: uuid.New(), Scoped: true,
			Scope: apitoken.Scope{Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapUploads: apitoken.AccessWrite}},
		})
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer backend.Close()

	// Stalled: a few bytes, then nothing while the connection stays open.
	conn, err := net.Dial("tcp", backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST "+uploadPath+" HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n{\"a\":"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, errUploadTooSlow) {
			t.Fatalf("stalled body read error = %v, want errUploadTooSlow", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled upload was not cut off")
	}
	// The slot is released once the handler returns.
	for deadline := time.Now().Add(5 * time.Second); len(srv.uploadSlots) != 0; {
		if time.Now().After(deadline) {
			t.Fatal("slot of the cut-off upload was not released")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A body that arrives at once passes, and processing time is not cut.
	response, err := http.Post(backend.URL+uploadPath, "application/json", strings.NewReader(strings.Repeat("x", 64<<10)))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if err := <-readErr; err != nil {
		t.Fatalf("fast body read error = %v", err)
	}
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("fast upload = %d, want 202", response.StatusCode)
	}
}

// http.trusted_proxy_header is honoured only when the peer is in the trusted
// CIDRs, so a client reaching hibou directly cannot pick its own IP.
func TestTrustedProxyClientIP(t *testing.T) {
	t.Parallel()

	if trustedProxyClientIP("", nil) != nil {
		t.Fatal("unconfigured trusted proxy must install nothing")
	}
	router := chi.NewRouter()
	configureRouter(router, zerolog.New(io.Discard), trustedProxyClientIP("CF-Connecting-IP", []netip.Prefix{netip.MustParsePrefix("173.245.48.0/20")}))
	router.Get("/ip", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, requestClientIP(r))
	})
	get := func(remote, xff, cf string) string {
		request := httptest.NewRequest(http.MethodGet, "/ip", nil)
		request.RemoteAddr = remote
		if xff != "" {
			request.Header.Set("X-Forwarded-For", xff)
		}
		if cf != "" {
			request.Header.Set("CF-Connecting-IP", cf)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder.Body.String()
	}

	// CDN edge → ingress → hibou: the ingress appended the edge IP.
	if got := get("10.0.0.5:1234", "173.245.48.10", "203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("via trusted CDN = %q, want the header IP", got)
	}
	// Direct to the ingress, header forged.
	if got := get("10.0.0.5:1234", "198.51.100.9", "203.0.113.7"); got != "198.51.100.9" {
		t.Errorf("untrusted peer = %q, want the forwarded peer, header ignored", got)
	}
	// No ingress: the TCP peer is the CDN edge.
	if got := get("173.245.48.10:443", "", "203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("trusted TCP peer = %q, want the header IP", got)
	}
	// Trusted peer without the header keeps the peer.
	if got := get("173.245.48.10:443", "", ""); got != "173.245.48.10" {
		t.Errorf("trusted peer without header = %q, want the peer", got)
	}
}

// Swagger UI (inline script, relaxed CSP) is only routed with
// api.docs.enabled.
func TestSwaggerDocsFollowConfig(t *testing.T) {
	t.Parallel()

	for _, enabled := range []bool{false, true} {
		srv := &Server{
			cfg:    config.Config{APIDocsEnabled: enabled},
			router: chi.NewRouter(),
			wsHub:  ws.NewHub(zerolog.New(io.Discard)),
			log:    zerolog.New(io.Discard),
		}
		configureRouter(srv.router, zerolog.New(io.Discard))
		srv.routes(nil)
		recorder := httptest.NewRecorder()
		srv.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/docs/index.html", nil))
		if served := recorder.Code == http.StatusOK; served != enabled {
			t.Errorf("api.docs.enabled=%v: GET /api/v1/docs/index.html = %d", enabled, recorder.Code)
		}
	}
}

// A signed-in user queues for an upload slot only as a member of some org;
// their uploads count against one key whatever token they use.
func TestUploadAdmissionRequiresOrgMembership(t *testing.T) {
	fixture := newAuthzFixture(t)
	member := fixture.invitedUser(t, "developer")
	outsider, err := fixture.srv.queries.CreateUser(context.Background(), uniqueName(t, "o")+"@example.com", "O", "github", uniqueName(t, "o"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	srv := fixture.srv
	srv.limits = effectiveLimits(config.LimitsConfig{})

	admit := func(request *http.Request) (int, []inFlightKey) {
		recorder := httptest.NewRecorder()
		keys, ok := srv.uploadAdmission(recorder, request)
		if ok {
			return http.StatusOK, keys
		}
		return recorder.Code, nil
	}
	asUser := func(user *store.User) *http.Request {
		request := httptest.NewRequest(http.MethodPost, uploadPath, nil)
		return request.WithContext(auth.WithUser(request.Context(), user))
	}

	if code, _ := admit(asUser(outsider)); code != http.StatusForbidden {
		t.Fatalf("user without an org = %d, want 403", code)
	}
	code, keys := admit(asUser(member))
	if code != http.StatusOK || len(keys) != 1 || keys[0].key != "user:"+member.ID.String() {
		t.Fatalf("member = %d %+v, want admitted under the user key", code, keys)
	}
}
