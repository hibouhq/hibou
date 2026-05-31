package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const ipRefreshInterval = 6 * time.Hour

// gitlabSaaSCIDRs are the published outbound IP ranges for GitLab.com SaaS.
// Source: https://docs.gitlab.com/ee/user/gitlab_com/#ip-range
// Override with AllowedCIDRs in forge config.
var gitlabSaaSCIDRs = []string{
	"34.74.90.64/28",
	"34.74.226.0/24",
}

// forgeIPSource dynamically fetches CIDR ranges for a forge's webhook source IPs.
type forgeIPSource interface {
	FetchCIDRs(ctx context.Context) ([]string, error)
	Name() string
}

// forgeIPAllowlist manages an auto-refreshing IP allowlist with optional
// static CIDRs and an optional dynamic source.
type forgeIPAllowlist struct {
	ctx               context.Context
	cancel            context.CancelFunc
	source            forgeIPSource
	static            []*net.IPNet
	staticConfigured  bool
	dynamic           []*net.IPNet
	dynamicConfigured bool
	mu                sync.RWMutex
	log               zerolog.Logger
}

// newForgeIPAllowlist creates an IP allowlist. If source is non-nil, it fetches
// CIDRs on startup and refreshes every 6 hours. staticCIDRs are parsed once
// and always allowed.
func newForgeIPAllowlist(ctx context.Context, log zerolog.Logger, source forgeIPSource, staticCIDRs []string) *forgeIPAllowlist {
	if ctx == nil {
		ctx = context.Background()
	}
	alCtx, cancel := context.WithCancel(ctx)

	componentName := "ip-allowlist"
	if source != nil {
		componentName = source.Name() + "-ip-allowlist"
	}

	a := &forgeIPAllowlist{
		ctx:               alCtx,
		cancel:            cancel,
		source:            source,
		staticConfigured:  len(staticCIDRs) > 0,
		dynamicConfigured: source != nil,
		log:               log.With().Str("component", componentName).Logger(),
	}

	for _, cidr := range staticCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			a.log.Error().Str("cidr", cidr).Err(err).Msg("invalid static CIDR, skipping")
			continue
		}
		a.static = append(a.static, ipNet)
	}

	if a.staticConfigured && len(a.static) == 0 {
		a.log.Error().Msg("static CIDRs configured but none parsed successfully; allowlist will reject all requests until fixed")
	}

	if source != nil {
		a.refresh()
		go a.refreshLoop()
	}

	a.log.Info().
		Int("static_ranges", len(a.static)).
		Bool("dynamic_source", source != nil).
		Msg("initialized IP allowlist")

	return a
}

func (a *forgeIPAllowlist) refreshLoop() {
	ticker := time.NewTicker(ipRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.refresh()
		}
	}
}

func (a *forgeIPAllowlist) refresh() {
	cidrs, err := a.source.FetchCIDRs(a.ctx)
	if err != nil {
		a.log.Error().Err(err).Msg("failed to fetch dynamic CIDRs")
		return
	}

	var nets []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			a.log.Warn().Str("cidr", cidr).Err(err).Msg("skipping invalid CIDR from source")
			continue
		}
		nets = append(nets, ipNet)
	}

	if len(nets) == 0 {
		a.log.Error().Msg("no valid dynamic CIDRs parsed, keeping previous list")
		return
	}

	a.mu.Lock()
	a.dynamic = nets
	a.mu.Unlock()

	a.log.Info().Int("ranges", len(nets)).Msg("refreshed dynamic IP allowlist")
}

func (a *forgeIPAllowlist) contains(ip net.IP) bool {
	for _, n := range a.static {
		if n.Contains(ip) {
			return true
		}
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, n := range a.dynamic {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *forgeIPAllowlist) loaded() bool {
	if a.staticConfigured || len(a.static) > 0 {
		return true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.dynamic) > 0
}

// Middleware returns an HTTP middleware that rejects requests not in the allowlist.
func (a *forgeIPAllowlist) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		ip := net.ParseIP(host)
		if ip == nil {
			a.log.Warn().Str("remote_addr", r.RemoteAddr).Msg("could not parse remote IP")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if !a.loaded() {
			a.log.Warn().Str("ip", ip.String()).Msg("IP allowlist not loaded yet; allowing request")
			next.ServeHTTP(w, r)
			return
		}

		if !a.contains(ip) {
			a.log.Debug().Str("ip", ip.String()).Msg("rejected request from non-allowed IP")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type githubMeta struct {
	Hooks   []string `json:"hooks"`
	Actions []string `json:"actions"`
}

type githubIPSource struct {
	metaURL string
	client  *http.Client
}

// newGitHubIPSource creates a GitHub IP source. For github.com (empty forgeURL),
// it uses api.github.com/meta. For GitHub Enterprise Server, it derives the
// /meta endpoint from the instance URL (e.g., https://ghes.corp.com/api/v3/meta).
func newGitHubIPSource(forgeURL string) *githubIPSource {
	metaURL := "https://api.github.com/meta"
	if forgeURL != "" {
		metaURL = strings.TrimRight(forgeURL, "/") + "/api/v3/meta"
	}
	return &githubIPSource{
		metaURL: metaURL,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *githubIPSource) Name() string { return "github-meta" }

func (s *githubIPSource) FetchCIDRs(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.metaURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub /meta returned status %d", resp.StatusCode)
	}

	var meta githubMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decoding GitHub /meta: %w", err)
	}

	return append(meta.Hooks, meta.Actions...), nil
}
