package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/ws"
)

func TestRequireBearerToken(t *testing.T) {
	t.Parallel()

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cases := []struct {
		name, token, header string
		want                int
	}{
		{"no token configured", "", "", http.StatusOK},
		{"missing header", "s3cret", "", http.StatusUnauthorized},
		{"wrong token", "s3cret", "Bearer nope", http.StatusUnauthorized},
		{"prefix of token", "s3cret", "Bearer s3c", http.StatusUnauthorized},
		{"wrong scheme", "s3cret", "Basic s3cret", http.StatusUnauthorized},
		{"right token", "s3cret", "Bearer s3cret", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			requireBearerToken(tc.token, ok).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// With metrics.port set, /metrics must be gone from the application router so
// an ingress forwarding the application port cannot expose it; with
// metrics.enabled=false it is gone everywhere.
func TestMetricsRouteOnlyWithoutDedicatedPort(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		enabled bool
		port    int
		want    bool
	}{{true, 0, true}, {true, 9090, false}, {false, 0, false}} {
		srv, _, _, _ := newDiscoveryTestServer(t)
		srv.cfg.Metrics.Enabled = tc.enabled
		srv.cfg.Metrics.Port = tc.port
		srv.router = chi.NewRouter()
		srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
		configureRouter(srv.router, zerolog.New(io.Discard))
		srv.routes(nil)

		found := false
		_ = chi.Walk(srv.router, func(_ string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if route == "/metrics" {
				found = true
			}
			return nil
		})
		if found != tc.want {
			t.Fatalf("metrics.enabled=%v port=%d: /metrics on app router = %v, want %v", tc.enabled, tc.port, found, tc.want)
		}
	}
}
