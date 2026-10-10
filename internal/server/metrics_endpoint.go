package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler serves the Prometheus registry, behind a bearer token when
// metrics.bearer_token is set (ADR-039 §5). cmd/serve.go mounts it on the
// dedicated metrics listener when metrics.port is set.
func (s *Server) MetricsHandler() http.Handler {
	return requireBearerToken(s.cfg.Metrics.BearerToken, promhttp.Handler())
}

// requireBearerToken passes requests through unchanged when token is empty.
// Both sides are hashed before the constant-time compare so neither the
// token's content nor its length leaks through timing.
func requireBearerToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		gotSum := sha256.Sum256([]byte(got))
		if !ok || subtle.ConstantTimeCompare(gotSum[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
