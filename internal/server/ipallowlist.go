package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store/dbgen"
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
	// onChange, when set, is told which ranges a refresh added and removed
	// (not on the initial load). Guarded by mu.
	onChange func(added, removed []string)
}

// SetChangeHook registers a callback for refreshes that change the dynamic
// ranges, so the change lands in the audit log.
func (a *forgeIPAllowlist) SetChangeHook(fn func(added, removed []string)) {
	a.mu.Lock()
	a.onChange = fn
	a.mu.Unlock()
}

// newForgeIPAllowlist creates an IP allowlist. If source is non-nil, it fetches
// CIDRs on startup and refreshes every 6 hours. staticCIDRs are parsed once
// and always allowed.
func newForgeIPAllowlist(ctx context.Context, log zerolog.Logger, source forgeIPSource, staticCIDRs []string) *forgeIPAllowlist {
	if ctx == nil {
		ctx = context.Background()
	}
	// #nosec G118 -- cancel is retained on the allowlist and invoked via server shutdown.
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
	previous := a.dynamic
	a.dynamic = nets
	hook := a.onChange
	a.mu.Unlock()

	added, removed := diffIPNets(previous, nets)
	if len(previous) > 0 && (len(added) > 0 || len(removed) > 0) {
		a.log.Info().Strs("added", added).Strs("removed", removed).Msg("dynamic IP allowlist changed")
		if hook != nil {
			hook(added, removed)
		}
	}
	a.log.Info().Int("ranges", len(nets)).Msg("refreshed dynamic IP allowlist")
}

// diffIPNets returns the CIDRs only in next (added) and only in previous
// (removed), sorted.
func diffIPNets(previous, next []*net.IPNet) (added, removed []string) {
	before := make(map[string]bool, len(previous))
	for _, n := range previous {
		before[n.String()] = true
	}
	after := make(map[string]bool, len(next))
	for _, n := range next {
		after[n.String()] = true
		if !before[n.String()] {
			added = append(added, n.String())
		}
	}
	for cidr := range before {
		if !after[cidr] {
			removed = append(removed, cidr)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// auditIPAllowlistChange returns a change hook that records a forge's
// webhook-source allowlist changes as system audit entries. Wire it with
// allowlist.SetChangeHook(s.auditIPAllowlistChange(forgeID)).
func (s *Server) auditIPAllowlistChange(forgeID string) func(added, removed []string) {
	return func(added, removed []string) {
		if s.queries == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		body, err := json.Marshal(map[string]any{
			"forge_id": forgeID,
			"added":    added,
			"removed":  removed,
		})
		if err != nil {
			return
		}
		if _, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
			ActorType:    audit.ActorSystem,
			ActorDisplay: "ip-allowlist-refresh",
			Action:       audit.ActionIPAllowlistChange,
			ResourceType: "forge",
			ResourceID:   forgeID,
			Context:      body,
		}); err != nil {
			s.log.Warn().Err(err).Str("forge_id", forgeID).Msg("audit log write failed for IP allowlist change")
		}
	}
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
		host := middleware.GetClientIP(r.Context())
		if host == "" {
			parsedHost, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			} else {
				host = parsedHost
			}
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
