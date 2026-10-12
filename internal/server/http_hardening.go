package server

import (
	"context"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
)

// Route classes the hardening middleware treat differently. Matched on the
// raw path because the body limit and connection deadlines run before chi
// has resolved a route.
const (
	apiPrefix         = "/api/v1/"
	uploadPath        = "/api/v1/upload"
	websocketPath     = "/api/v1/ws"
	secretCheckPath   = "/api/v1/secret-scan/check" // #nosec G101 -- route path, not a credential
	toolSBOMCompare   = "/api/v1/tools/sbom/compare"
	swaggerDocsPrefix = "/api/v1/docs/"
	webhooksPrefix    = "/api/v1/webhooks/"
	binPrefix         = "/api/v1/bin/"
	orgsPrefix        = "/api/v1/orgs/"
	// downloadWriteTimeout bounds how long a slow reader may hold a download.
	downloadWriteTimeout = time.Hour
)

func isSBOMComparePath(path string) bool {
	return path == toolSBOMCompare || (strings.HasPrefix(path, orgsPrefix) && strings.HasSuffix(path, "/sbom/compare"))
}

// isDownloadPath matches responses that stream files and may outlast the
// write timeout on a slow link.
func isDownloadPath(path string) bool {
	if strings.HasPrefix(path, binPrefix) {
		return true
	}
	if !strings.HasPrefix(path, orgsPrefix) {
		return false
	}
	return (strings.Contains(path, "/snapshots/") && strings.Contains(path, "/files")) ||
		strings.Contains(path, "/compliance/") ||
		strings.HasSuffix(path, "/vex/export")
}

// isLongRunningPath matches authenticated routes exempt from the request
// timeout: they carry their own bound (upload size, secret_scan.timeout) or
// legitimately run longer (synchronous scans, downloads).
func isLongRunningPath(path string) bool {
	return path == uploadPath ||
		path == secretCheckPath ||
		isDownloadPath(path) ||
		strings.HasSuffix(path, "/components/scan")
}

// effectiveLimits fills zero fields from the defaults, so a Server built
// without config.Load (tests, embedders) still gets bounded behaviour.
func effectiveLimits(cfg config.LimitsConfig) config.LimitsConfig {
	defaults := config.DefaultLimits()
	if cfg.DB.MaxOpenConns <= 0 {
		cfg.DB = defaults.DB
	}
	if cfg.HTTP.ReadTimeout <= 0 {
		cfg.HTTP.ReadTimeout = defaults.HTTP.ReadTimeout
	}
	if cfg.HTTP.UploadReadTimeout <= 0 {
		cfg.HTTP.UploadReadTimeout = defaults.HTTP.UploadReadTimeout
	}
	if cfg.HTTP.WriteTimeout <= 0 {
		cfg.HTTP.WriteTimeout = defaults.HTTP.WriteTimeout
	}
	if cfg.HTTP.RequestTimeout <= 0 {
		cfg.HTTP.RequestTimeout = defaults.HTTP.RequestTimeout
	}
	if cfg.HTTP.MaxHeaderBytes <= 0 {
		cfg.HTTP.MaxHeaderBytes = defaults.HTTP.MaxHeaderBytes
	}
	if cfg.HTTP.MaxBodyBytes <= 0 {
		cfg.HTTP.MaxBodyBytes = defaults.HTTP.MaxBodyBytes
	}
	if cfg.HTTP.WebhookMaxBodyBytes <= 0 {
		cfg.HTTP.WebhookMaxBodyBytes = defaults.HTTP.WebhookMaxBodyBytes
	}
	if cfg.Upload.MaxConcurrent <= 0 {
		cfg.Upload.MaxConcurrent = defaults.Upload.MaxConcurrent
	}
	if cfg.Upload.QueueWait <= 0 {
		cfg.Upload.QueueWait = defaults.Upload.QueueWait
	}
	if cfg.Upload.MaxItems <= 0 {
		cfg.Upload.MaxItems = defaults.Upload.MaxItems
	}
	if cfg.Upload.ProcessingConcurrency <= 0 {
		cfg.Upload.ProcessingConcurrency = defaults.Upload.ProcessingConcurrency
	}
	// RateLimit.Enabled is not defaulted: a zero config means "off".
	return cfg
}

// bodyLimitFor is the request body cap of a path: 1 MB unless the route is
// one of the few that take documents.
func (s *Server) bodyLimitFor(path string) int64 {
	switch {
	case path == uploadPath:
		if s.cfg.MaxUploadSize > 0 {
			return s.cfg.MaxUploadSize
		}
		return defaultMaxUploadSize
	case strings.HasPrefix(path, webhooksPrefix):
		return s.limits.HTTP.WebhookMaxBodyBytes
	case isSBOMComparePath(path):
		return maxSBOMCompareBytes
	default:
		return s.limits.HTTP.MaxBodyBytes
	}
}

// bodyLimitMiddleware caps every request body. Handlers that decode JSON
// straight from r.Body then fail on a MaxBytesError instead of buffering
// whatever a client sends.
func (s *Server) bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			limit := s.bodyLimitFor(r.URL.Path)
			if r.ContentLength > limit {
				api.JSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// connectionDeadlineMiddleware adjusts the server-wide read/write deadlines
// for routes that need a different budget: websockets live for hours,
// uploads read up to max.upload.size, downloads stream to slow clients.
func (s *Server) connectionDeadlineMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		now := time.Now()
		path := r.URL.Path
		switch {
		case path == websocketPath:
			// The hijacked connection keeps whatever deadline is set now.
			_ = controller.SetReadDeadline(time.Time{})
			_ = controller.SetWriteDeadline(time.Time{})
		case path == uploadPath:
			_ = controller.SetReadDeadline(now.Add(s.limits.HTTP.UploadReadTimeout))
			_ = controller.SetWriteDeadline(now.Add(s.limits.HTTP.UploadReadTimeout + s.limits.HTTP.WriteTimeout))
		case isDownloadPath(path):
			_ = controller.SetWriteDeadline(now.Add(downloadWriteTimeout))
		}
		next.ServeHTTP(w, r)
	})
}

// requestTimeoutMiddleware bounds an ordinary API request's context, so a
// slow query or forge call is cancelled instead of holding a connection and a
// pool slot. Long-running routes are exempt (isLongRunningPath).
func (s *Server) requestTimeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLongRunningPath(r.URL.Path) || s.limits.HTTP.RequestTimeout <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.limits.HTTP.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// securityHeadersMiddleware sets the browser hardening headers on every
// response. The SPA bundle is self-hosted with no inline script; Vue and
// Chart.js set inline styles, and avatars come from forge hosts, hence the
// style and img allowances. API responses never render, so they get a
// sandboxing policy that also covers raw artifact downloads. Swagger UI ships
// an inline bootstrap script and gets its own relaxed policy.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	spaPolicy := spaContentSecurityPolicy(s.cfg.BaseURL)
	hsts := strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.cfg.BaseURL)), "https://")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if hsts {
			header.Set("Strict-Transport-Security", "max-age=31536000")
		}
		switch path := r.URL.Path; {
		case strings.HasPrefix(path, swaggerDocsPrefix):
			header.Set("Content-Security-Policy", swaggerContentSecurityPolicy)
		case strings.HasPrefix(path, apiPrefix) || path == "/metrics":
			header.Set("Content-Security-Policy", apiContentSecurityPolicy)
		default:
			header.Set("Content-Security-Policy", spaPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

const (
	apiContentSecurityPolicy     = "default-src 'none'; frame-ancestors 'none'; sandbox"
	swaggerContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

func spaContentSecurityPolicy(baseURL string) string {
	connect := "'self'"
	// Older Safari does not let 'self' cover ws(s): name the origin outright.
	if parsed, err := url.Parse(strings.TrimSpace(baseURL)); err == nil && parsed.Host != "" {
		switch parsed.Scheme {
		case "https":
			connect += " wss://" + parsed.Host
		case "http":
			connect += " ws://" + parsed.Host
		}
	}
	return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob: https:; font-src 'self' data:; connect-src " + connect + "; " +
		"worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
}

// rateLimiters holds the token buckets of rate_limit.*. A nil field means
// that class is not limited.
type rateLimiters struct {
	api       *ipRateLimiter
	upload    *ipRateLimiter
	scan      *ipRateLimiter
	auth      *ipRateLimiter
	anonymous *ipRateLimiter
}

func newRateLimiters(ctx context.Context, cfg config.RateLimitConfig) rateLimiters {
	if !cfg.Enabled {
		return rateLimiters{}
	}
	build := func(bucket config.RateLimitBucket) *ipRateLimiter {
		return newIPRateLimiter(ctx, bucket.RPS, bucket.Burst)
	}
	return rateLimiters{
		api:       build(cfg.API),
		upload:    build(cfg.Upload),
		scan:      build(cfg.Scan),
		auth:      build(cfg.Auth),
		anonymous: build(cfg.Anonymous),
	}
}

func requestClientIP(r *http.Request) string {
	if host := middleware.GetClientIP(r.Context()); host != "" {
		return host
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// principalRateKey keys a bucket by API key, else user, else client IP, so a
// CI fleet behind one NAT shares nothing with a person using the UI.
func principalRateKey(r *http.Request) string {
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth != nil {
		return "key:" + tokenAuth.KeyID.String()
	}
	if user := UserFromContext(r.Context()); user != nil {
		return "user:" + user.ID.String()
	}
	return "ip:" + requestClientIP(r)
}

func ipRateKey(r *http.Request) string {
	return "ip:" + requestClientIP(r)
}

// rateLimitMiddleware answers 429 with Retry-After once a key's bucket is
// empty. A nil limiter passes everything through.
func rateLimitMiddleware(limiter *ipRateLimiter, key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if limiter == nil {
			return next
		}
		retryAfter := "1"
		if limiter.rate > 0 && float64(limiter.rate) < 1 {
			retryAfter = strconv.Itoa(int(math.Ceil(1 / float64(limiter.rate))))
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.getLimiter(key(r)).Allow() {
				w.Header().Set("Retry-After", retryAfter)
				api.JSONError(w, http.StatusTooManyRequests, "rate limit exceeded, retry later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// uploadConcurrencyMiddleware holds at most upload.max_concurrent uploads in
// flight per replica: each one buffers its decoded artifact several times
// over, so the cap is what keeps a burst of CI jobs from exhausting memory.
// A request waits up to upload.queue_wait for a slot, then gets 503.
func (s *Server) uploadConcurrencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(s.limits.Upload.QueueWait)
		defer timer.Stop()
		select {
		case s.uploadSlots <- struct{}{}:
			defer func() { <-s.uploadSlots }()
			next.ServeHTTP(w, r)
		case <-timer.C:
			w.Header().Set("Retry-After", "30")
			api.JSONError(w, http.StatusServiceUnavailable, "upload capacity reached, retry later")
		case <-r.Context().Done():
		}
	})
}
