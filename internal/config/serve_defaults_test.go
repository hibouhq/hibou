package config

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Self-hosting defaults: MCP and Swagger UI are opt-in outside development,
// /metrics gets its own port.
func TestLoadSecureServeDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MCPEnabled || cfg.APIDocsEnabled {
		t.Errorf("mcp.enabled=%v api.docs.enabled=%v, want both off outside development", cfg.MCPEnabled, cfg.APIDocsEnabled)
	}
	if cfg.Metrics.Port != 9090 {
		t.Errorf("metrics.port = %d, want 9090", cfg.Metrics.Port)
	}
	if cfg.AutoProvisionOrgs {
		t.Error("auto.provision.orgs default on, want off")
	}
	upload := cfg.Limits.Upload
	if upload.MaxConcurrentPerPrincipal != 2 || upload.MaxConcurrentPerOrg != 2 || upload.MinThroughputBytes != 16<<10 || upload.MinThroughputWindow != 30*time.Second {
		t.Errorf("upload limits = %+v, want per-principal/org 2, 16 KiB per 30s", upload)
	}
	if cfg.Limits.HTTP.TrustedProxyHeader != "" || len(cfg.Limits.HTTP.TrustedProxyCIDRs) != 0 {
		t.Errorf("trusted proxy on by default: %+v", cfg.Limits.HTTP)
	}

	t.Setenv("HIBOU_DEVELOPMENT", "true")
	dev, err := Load()
	if err != nil {
		t.Fatalf("Load() development error = %v", err)
	}
	if !dev.MCPEnabled || !dev.APIDocsEnabled {
		t.Errorf("development: mcp.enabled=%v api.docs.enabled=%v, want both on", dev.MCPEnabled, dev.APIDocsEnabled)
	}

	t.Setenv("HIBOU_API_DOCS_ENABLED", "false")
	t.Setenv("HIBOU_MCP_ENABLED", "false")
	explicit, err := Load()
	if err != nil {
		t.Fatalf("Load() explicit error = %v", err)
	}
	if explicit.MCPEnabled || explicit.APIDocsEnabled {
		t.Error("explicit false must win over the development default")
	}
}

func TestLoadAllowedOrigins(t *testing.T) {
	t.Setenv("HIBOU_ALLOWED_ORIGINS", "https://Hibou.Example.com/, http://localhost:3000,https://hibou.example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := strings.Join(cfg.AllowedOrigins, " "); got != "https://hibou.example.com http://localhost:3000" {
		t.Fatalf("allowed origins = %q", got)
	}

	for _, bad := range []string{"hibou.example.com", "https://hibou.example.com/app", "ftp://x", "https://u:p@x"} {
		t.Setenv("HIBOU_ALLOWED_ORIGINS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("allowed_origins %q accepted", bad)
		}
	}
}

func TestLoadTrustedProxy(t *testing.T) {
	t.Setenv("HIBOU_HTTP_TRUSTED_PROXY_HEADER", "CF-Connecting-IP")
	t.Setenv("HIBOU_HTTP_TRUSTED_PROXY_CIDRS", "173.245.48.0/20, 2400:cb00::/32")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("173.245.48.0/20"), netip.MustParsePrefix("2400:cb00::/32")}
	if cfg.Limits.HTTP.TrustedProxyHeader != "CF-Connecting-IP" || len(cfg.Limits.HTTP.TrustedProxyCIDRs) != 2 ||
		cfg.Limits.HTTP.TrustedProxyCIDRs[0] != want[0] || cfg.Limits.HTTP.TrustedProxyCIDRs[1] != want[1] {
		t.Fatalf("trusted proxy = %q %v", cfg.Limits.HTTP.TrustedProxyHeader, cfg.Limits.HTTP.TrustedProxyCIDRs)
	}

	// A header nobody is trusted to set would let any client pick its IP.
	t.Setenv("HIBOU_HTTP_TRUSTED_PROXY_CIDRS", "")
	if _, err := Load(); err == nil {
		t.Error("trusted proxy header without CIDRs accepted")
	}
	t.Setenv("HIBOU_HTTP_TRUSTED_PROXY_CIDRS", "not-a-cidr")
	if _, err := Load(); err == nil {
		t.Error("invalid trusted proxy CIDR accepted")
	}
}

func TestValidateServe(t *testing.T) {
	secure := Config{BaseURL: "https://hibou.example.com", Metrics: MetricsConfig{Enabled: true, Port: 9090}}
	if err := secure.ValidateServe(zerolog.Nop()); err != nil {
		t.Fatalf("secure config refused: %v", err)
	}

	for name, cfg := range map[string]Config{
		"empty base url":         {Metrics: MetricsConfig{Enabled: true, Port: 9090}},
		"relative base url":      {BaseURL: "hibou.example.com", Metrics: MetricsConfig{Enabled: true, Port: 9090}},
		"metrics on app port":    {BaseURL: "https://hibou.example.com", Metrics: MetricsConfig{Enabled: true}},
		"both, still one error":  {Metrics: MetricsConfig{Enabled: true}},
		"unsupported url scheme": {BaseURL: "ftp://hibou.example.com"},
	} {
		if err := cfg.ValidateServe(zerolog.Nop()); err == nil {
			t.Errorf("%s: accepted outside development", name)
		}
	}

	// Token-protected /metrics on the app port and disabled metrics are fine.
	for _, metrics := range []MetricsConfig{{Enabled: true, BearerToken: "t"}, {Enabled: false}} {
		cfg := Config{BaseURL: "https://hibou.example.com", Metrics: metrics}
		if err := cfg.ValidateServe(zerolog.Nop()); err != nil {
			t.Errorf("metrics %+v refused: %v", metrics, err)
		}
	}

	// Development starts anyway, loudly.
	var logs bytes.Buffer
	dev := Config{Development: true, Metrics: MetricsConfig{Enabled: true}}
	if err := dev.ValidateServe(zerolog.New(&logs)); err != nil {
		t.Fatalf("development refused: %v", err)
	}
	if !strings.Contains(logs.String(), "base.url") || !strings.Contains(logs.String(), "/metrics") {
		t.Fatalf("development warnings missing: %s", logs.String())
	}
}

func TestValidateServeRefusesNonHTTPSCVEFeedRemote(t *testing.T) {
	base := Config{BaseURL: "https://hibou.example.com", Metrics: MetricsConfig{Enabled: true, Port: 9090}}
	for _, remote := range []string{"git@github.com:org/repo.git", "-uupload-pack=x", "http://example.com/feed.git", "/srv/feed"} {
		cfg := base
		cfg.CVEFeed.Remote = remote
		if err := cfg.ValidateServe(zerolog.Nop()); err == nil {
			t.Errorf("remote %q accepted, want refused", remote)
		}
	}
	for _, remote := range []string{"", "https://github.com/CVEProject/cvelistV5.git", "file:///srv/feed"} {
		cfg := base
		cfg.CVEFeed.Remote = remote
		if err := cfg.ValidateServe(zerolog.Nop()); err != nil {
			t.Errorf("remote %q refused: %v", remote, err)
		}
	}
}
