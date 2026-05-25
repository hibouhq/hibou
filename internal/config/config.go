// Package config provides environment-based configuration for the hibou server.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	Host          string        `env:"HIBOU_HOST"            envDefault:"0.0.0.0"`
	Port          int           `env:"HIBOU_PORT"            envDefault:"8080"`
	MCPEnabled    bool          `env:"HIBOU_MCP_ENABLED"     envDefault:"true"`
	MCPPort       int           `env:"HIBOU_MCP_PORT"        envDefault:"8081"`
	BaseURL       string        `env:"HIBOU_BASE_URL"`
	DatabaseURL   string        `env:"HIBOU_DATABASE_URL"    envDefault:"postgres://hibou:hibou@localhost:5432/hibou?sslmode=disable"`
	LogLevel      string        `env:"HIBOU_LOG_LEVEL"       envDefault:"info"`
	LogFormat     string        `env:"HIBOU_LOG_FORMAT"      envDefault:"console"`
	TriviURL      string        `env:"HIBOU_TRIVY_URL"       envDefault:"http://localhost:4954"`
	OSVURL        string        `env:"HIBOU_OSV_URL"         envDefault:"https://api.osv.dev"`
	CacheTTL      time.Duration `env:"HIBOU_CACHE_TTL"       envDefault:"6h"`
	ArtifactPath  string        `env:"HIBOU_ARTIFACT_PATH"   envDefault:"/data/artifacts"`
	SessionSecret string        `env:"HIBOU_SESSION_SECRET"  envDefault:"change-me-in-production"`

	Forges []ForgeConfig
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
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
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
		})
	}

	return configs
}
