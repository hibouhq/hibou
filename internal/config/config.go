// Package config provides environment-based configuration for the hibou server.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Host              string
	Port              int
	MCPEnabled        bool
	MCPPort           int
	BaseURL           string
	DatabaseURL       string
	LogLevel          string
	LogFormat         string
	TriviURL          string
	OSVURL            string
	CacheTTL          time.Duration
	ArtifactPath      string
	UploadWindow      time.Duration
	MaxUploadSize     int64
	SessionSecret     string
	AutoProvisionOrgs bool
	SecretScan        SecretScanConfig

	Forges []ForgeConfig
}

type SecretScanConfig struct {
	Enabled   bool
	Providers []string
	TempDir   string
	OnPush    bool
}

// ForgeConfig holds configuration for a single forge instance.
// Populated from indexed env vars: HIBOU_FORGE_0_TYPE, HIBOU_FORGE_0_ID, etc.
type ForgeConfig struct {
	// Type is the forge type: "github", "forgejo", "gitlab".
	Type string
	// ID is the unique identifier used in routes and DB records.
	// Defaults to Type if not set. Use custom IDs for multiple instances
	// of the same type (e.g., "forgejo-staging", "forgejo-prod").
	ID string
	// URL is the base URL for self-hosted instances. Not needed for github.com.
	URL string
	// ClientID is the OAuth2 application client ID.
	ClientID string
	// ClientSecret is the OAuth2 application client secret.
	ClientSecret string
	// WebhookSecret is the secret used to validate webhook payloads.
	WebhookSecret string
	// AppID is the GitHub App ID. When set with PrivateKey, enables GitHub App mode.
	AppID int64
	// PrivateKey is the PEM-encoded private key for the GitHub App.
	PrivateKey string
	// IPAllowlist enables source IP allowlisting on webhook routes for this forge.
	// For GitHub forges, IPs are auto-refreshed from the /meta endpoint.
	IPAllowlist bool
	// RateLimitRPS is the per-IP rate limit in requests/second for this forge's webhook routes (0 = disabled).
	RateLimitRPS float64
	// AllowedCIDRs is a comma-separated list of CIDR ranges allowed on webhook routes.
	// For static IP allowlisting (GitLab SaaS, self-hosted forges).
	// For GitHub forges, IPs are auto-fetched; this field provides additional static ranges.
	AllowedCIDRs string
}

func (c Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c Config) MCPListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.MCPPort)
}

// CookieDomain returns the domain for session cookies.
// Derived from HIBOU_BASE_URL hostname. Empty in dev (host-only cookie).
func (c Config) CookieDomain() string {
	if c.BaseURL == "" {
		return ""
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// CookieSecure returns whether cookies require HTTPS.
// True when HIBOU_BASE_URL uses https scheme.
func (c Config) CookieSecure() bool {
	if c.BaseURL == "" {
		return false
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return false
	}
	return u.Scheme == "https"
}

func Load() (Config, error) {
	v := viper.New()

	v.SetEnvPrefix("HIBOU")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.SetDefault("host", "0.0.0.0")
	v.SetDefault("port", 8585)
	v.SetDefault("mcp.enabled", true)
	v.SetDefault("mcp.port", 8081)
	v.SetDefault("base.url", "")
	v.SetDefault("database.url", "postgres://hibou:hibou@localhost:5432/hibou?sslmode=disable")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "console")
	v.SetDefault("trivy.url", "http://localhost:4954")
	v.SetDefault("osv.url", "https://api.osv.dev")
	v.SetDefault("cache.ttl", "6h")
	v.SetDefault("artifact.path", "/data/artifacts")
	v.SetDefault("upload.window", "10m")
	v.SetDefault("max.upload.size", int64(104857600))
	v.SetDefault("session.secret", "change-me-in-production")
	v.SetDefault("auto.provision.orgs", false)
	v.SetDefault("secret_scan.enabled", false)
	v.SetDefault("secret_scan.providers", []string{})
	v.SetDefault("secret_scan.temp_dir", "")
	v.SetDefault("secret_scan.on_push", false)

	v.SetConfigName("hibou-server")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/hibou")
	v.AddConfigPath(os.ExpandEnv("$HOME/.config/hibou"))

	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundErr viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundErr) {
			return Config{}, fmt.Errorf("reading config file: %w", err)
		}
	}

	cacheTTL, err := time.ParseDuration(v.GetString("cache.ttl"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing cache_ttl: %w", err)
	}
	uploadWindow, err := parseUploadWindow(v.GetString("upload.window"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing upload.window: %w", err)
	}

	cfg := Config{
		Host:              v.GetString("host"),
		Port:              v.GetInt("port"),
		MCPEnabled:        v.GetBool("mcp.enabled"),
		MCPPort:           v.GetInt("mcp.port"),
		BaseURL:           v.GetString("base.url"),
		DatabaseURL:       v.GetString("database.url"),
		LogLevel:          v.GetString("log.level"),
		LogFormat:         v.GetString("log.format"),
		TriviURL:          v.GetString("trivy.url"),
		OSVURL:            v.GetString("osv.url"),
		CacheTTL:          cacheTTL,
		ArtifactPath:      v.GetString("artifact.path"),
		UploadWindow:      uploadWindow,
		MaxUploadSize:     v.GetInt64("max.upload.size"),
		SessionSecret:     v.GetString("session.secret"),
		AutoProvisionOrgs: v.GetBool("auto.provision.orgs"),
		SecretScan: SecretScanConfig{
			Enabled:   v.GetBool("secret_scan.enabled"),
			Providers: normalizeList(v.GetStringSlice("secret_scan.providers")),
			TempDir:   strings.TrimSpace(v.GetString("secret_scan.temp_dir")),
			OnPush:    v.GetBool("secret_scan.on_push"),
		},
	}

	cfg.Forges = loadForgeConfigs()
	return cfg, nil
}

// loadForgeConfigs reads indexed HIBOU_FORGE_N_* environment variables.
// Example:
//
//	HIBOU_FORGE_0_TYPE=forgejo
//	HIBOU_FORGE_0_ID=my-forgejo
//	HIBOU_FORGE_0_URL=http://localhost:3030
//	HIBOU_FORGE_0_CLIENT_ID=abc
//	HIBOU_FORGE_0_CLIENT_SECRET=def
//	HIBOU_FORGE_0_WEBHOOK_SECRET=ghi
func loadForgeConfigs() []ForgeConfig {
	var configs []ForgeConfig

	for i := 0; ; i++ {
		prefix := "HIBOU_FORGE_" + strconv.Itoa(i) + "_"
		forgeType := strings.TrimSpace(os.Getenv(prefix + "TYPE"))
		if forgeType == "" {
			break
		}

		id := strings.TrimSpace(os.Getenv(prefix + "ID"))
		if id == "" {
			id = forgeType
		}

		configs = append(configs, ForgeConfig{
			Type:          forgeType,
			ID:            id,
			URL:           strings.TrimSpace(os.Getenv(prefix + "URL")),
			ClientID:      strings.TrimSpace(os.Getenv(prefix + "CLIENT_ID")),
			ClientSecret:  strings.TrimSpace(os.Getenv(prefix + "CLIENT_SECRET")),
			WebhookSecret: strings.TrimSpace(os.Getenv(prefix + "WEBHOOK_SECRET")),
			AppID:         parseForgeInt64(prefix + "APP_ID"),
			PrivateKey:    strings.TrimSpace(os.Getenv(prefix + "PRIVATE_KEY")),
			IPAllowlist:   strings.EqualFold(strings.TrimSpace(os.Getenv(prefix+"IP_ALLOWLIST")), "true"),
			RateLimitRPS:  parseForgeFloat64(prefix + "RATE_LIMIT_RPS"),
			AllowedCIDRs:  strings.TrimSpace(os.Getenv(prefix + "ALLOWED_CIDRS")),
		})
	}

	return configs
}

func parseUploadWindow(value string) (time.Duration, error) {
	const defaultUploadWindow = 10 * time.Minute

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultUploadWindow, nil
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return defaultUploadWindow, nil
	}

	return duration, nil
}

func parseForgeInt64(envKey string) int64 {
	value := strings.TrimSpace(os.Getenv(envKey))
	if value == "" {
		return 0
	}

	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}

func parseForgeFloat64(envKey string) float64 {
	value := strings.TrimSpace(os.Getenv(envKey))
	if value == "" {
		return 0
	}

	parsed, _ := strconv.ParseFloat(value, 64)
	return parsed
}

func normalizeList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}
