package cliclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoRetriesShedResponses(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"upload capacity reached"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()

	var waits []time.Duration
	retrySleep = func(d time.Duration) { waits = append(waits, d) }
	defer func() { retrySleep = time.Sleep }()

	c := &Client{Server: srv.URL, Token: "t", HTTPClient: srv.Client()}
	var out struct{ OK bool }
	if err := c.Post("/upload", map[string]string{"a": "b"}, &out); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if !out.OK || calls.Load() != 3 {
		t.Fatalf("ok=%v calls=%d, want true/3", out.OK, calls.Load())
	}
	if len(waits) != 2 || waits[0] != 2*time.Second {
		t.Fatalf("waits = %v, want two 2s waits", waits)
	}
}

func TestDoGivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	retrySleep = func(time.Duration) {}
	defer func() { retrySleep = time.Sleep }()

	c := &Client{Server: srv.URL, Token: "t", HTTPClient: srv.Client()}
	err := c.Get("/x", nil)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want 429", err)
	}
	if calls.Load() != maxRetryAttempts {
		t.Fatalf("calls = %d, want %d", calls.Load(), maxRetryAttempts)
	}
}

func TestDoDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	c := &Client{Server: srv.URL, Token: "t", HTTPClient: srv.Client()}
	if err := c.Get("/x", nil); err == nil || calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d, want error after 1 call", err, calls.Load())
	}
}

func TestRetryAfterBounds(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 5 * time.Second, "abc": 5 * time.Second, "3": 3 * time.Second, "3600": 60 * time.Second} {
		if got := retryAfter(in); got != want {
			t.Errorf("retryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}

// A 503 may come from a proxy after the server acted: a POST is not repeated
// (it could upload twice), a GET is.
func TestDoRetries503OnlyForIdempotentMethods(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	retrySleep = func(time.Duration) {}
	defer func() { retrySleep = time.Sleep }()

	c := &Client{Server: srv.URL, Token: "t", HTTPClient: srv.Client()}
	if err := c.Post("/upload", map[string]string{"a": "b"}, nil); err == nil || calls.Load() != 1 {
		t.Fatalf("POST on 503: err=%v calls=%d, want an error after 1 call", err, calls.Load())
	}
	calls.Store(0)
	if err := c.Get("/x", nil); err == nil || calls.Load() != maxRetryAttempts {
		t.Fatalf("GET on 503: err=%v calls=%d, want %d calls", err, calls.Load(), maxRetryAttempts)
	}
}

// The token never follows a redirect to another host or from https to http.
func TestCheckRedirectProtectsToken(t *testing.T) {
	var leaked atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/same" {
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}
		if r.URL.Path == "/api/v1/local" {
			http.Redirect(w, r, "/api/v1/same", http.StatusFound)
			return
		}
		http.Redirect(w, r, other.URL+"/api/v1/x", http.StatusFound)
	}))
	defer origin.Close()

	httpClient := origin.Client()
	httpClient.CheckRedirect = CheckRedirect
	c := &Client{Server: origin.URL, Token: "secret", HTTPClient: httpClient}
	if err := c.Get("/cross", nil); err == nil || !strings.Contains(err.Error(), "another host") {
		t.Fatalf("cross-host redirect err = %v, want refused", err)
	}
	if got, _ := leaked.Load().(string); got != "" {
		t.Fatalf("token reached the other host: %q", got)
	}
	if err := c.Get("/local", nil); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}

	from := httptest.NewRequest(http.MethodGet, "https://hibou.example.com/api/v1/x", nil)
	from.Header.Set("Authorization", "Bearer secret")
	to := httptest.NewRequest(http.MethodGet, "http://hibou.example.com/api/v1/x", nil)
	to.Header.Set("Authorization", "Bearer secret")
	if err := CheckRedirect(to, []*http.Request{from}); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Fatalf("https->http redirect err = %v, want refused", err)
	}
	anonymous := httptest.NewRequest(http.MethodGet, "https://hibou.example.com/x", nil)
	elsewhere := httptest.NewRequest(http.MethodGet, "http://cdn.example.com/x", nil)
	if err := CheckRedirect(elsewhere, []*http.Request{anonymous}); err != nil {
		t.Fatalf("redirect without a token refused: %v", err)
	}
}
