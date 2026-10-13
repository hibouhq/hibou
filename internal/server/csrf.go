package server

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/auth"
)

// csrfProtection rejects cross-site state-changing requests that would ride
// the session cookie. SameSite=Lax already withholds the cookie from most
// cross-site POSTs; this closes the rest (same-site sibling subdomains,
// browsers without SameSite) using the headers browsers attach and pages
// cannot forge:
//
//   - Sec-Fetch-Site, when present, must be "same-origin" or "none"
//     (user-initiated navigation); "same-site" and "cross-site" are refused.
//   - Origin, when present, must equal the instance origin (HIBOU_BASE_URL,
//     or the request host when no base URL is configured). In development a
//     loopback origin also passes: the Vite dev server proxies the SPA from
//     another port.
//
// Safe methods, bearer-token requests without a session cookie (a page cannot
// attach an Authorization header cross-origin without a CORS preflight hibou
// never grants) and forge
// webhooks (no cookie, authenticated by signature) are exempt. Non-browser
// clients send neither header and pass.
func (s *Server) csrfProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !csrfRequestAllowed(r, s.cfg.BaseURL, s.cfg.IsDevelopment(), s.cfg.AllowedOrigins...) {
			api.JSONError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allowedOrigins are extra instance origins (Config.AllowedOrigins, already
// normalized to lowercase scheme://host); they pass the Origin check only, the
// Sec-Fetch-Site refusal still applies.
func csrfRequestAllowed(r *http.Request, baseURL string, development bool, allowedOrigins ...string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	// A bearer request is exempt only without a session cookie: SessionAuth
	// authenticates the cookie first, so "Bearer x" next to a cookie would
	// otherwise carry a cross-site write on the victim's session.
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && !auth.HasSessionCookie(r) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/webhooks/") {
		return true
	}

	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" {
		if site != "same-origin" && site != "none" {
			return false
		}
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return originMatches(origin, baseURL, r.Host) || (development && isLoopbackOrigin(origin)) ||
			slices.Contains(allowedOrigins, strings.ToLower(origin))
	}
	return true
}

func isLoopbackOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// originMatches compares an Origin header with the instance origin. Without a
// base URL (development) only the host is compared, against the request's.
func originMatches(origin, baseURL, requestHost string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	if strings.TrimSpace(baseURL) == "" {
		return strings.EqualFold(parsed.Host, requestHost)
	}
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, base.Scheme) && strings.EqualFold(parsed.Host, base.Host)
}
