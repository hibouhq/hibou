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
			w.WriteHeader(http.StatusServiceUnavailable)
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
