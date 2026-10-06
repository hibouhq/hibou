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

	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/hibouhq/hibou/internal/retention"
)

const DefaultSessionSecret = "change-me-in-production"

type Config struct {
	Host              string
	Port              int
	Development       bool
	MCPEnabled        bool
	MCPPort           int
	BaseURL           string
	DatabaseURL       string
	LogLevel          string
	LogFormat         string
	TriviURL          string
	OSVURL            string
	CacheTTL          time.Duration
	ArtifactBackend   string
	ArtifactPath      string
	ArtifactS3        ArtifactS3Config
	UploadWindow      time.Duration
	ShutdownTimeout   time.Duration
	MaxUploadSize     int64
	SessionSecret     string
	AutoProvisionOrgs bool
	// InstanceAdmins lists the emails of hibou instance administrators
	// (HIBOU_INSTANCE_ADMINS, comma-separated, case-insensitive). Instance
	// admins manage instance-wide settings such as announcement banners; the
	// role is unrelated to org or repo admin membership.
	InstanceAdmins []string
	// InstanceAdminsFile points at a file holding the same list (comma- or
	// newline-separated), re-read on every authorization check. Mount a
	// Kubernetes Secret as a volume and point this at it: editing the Secret
	// then takes effect within the kubelet sync period, no restart and no
	// email in git or Helm values. Takes precedence over InstanceAdmins.
	InstanceAdminsFile string
	// CoverageStoreLines controls whether per-line coverage hit data is
	// persisted on upload (powers line-level patch coverage). Defaults to
	// true; set HIBOU_COVERAGE_STORE_LINES=false to opt out on very large
	// monorepos where per-line rows would balloon the database.
	CoverageStoreLines bool
	// AuditRetentionMonths is the hot-retention window for audit_logs: monthly
	// partitions fully older than this many months are dropped by the retention
	// pass. 0 (the default) keeps everything forever.
	AuditRetentionMonths int
	// AdvisoryEventRetentionMonths is the same window for the advisory activity
	// timeline (advisory_events). It is a narrative, not a compliance record,
	// so it gets its own knob rather than riding the audit one. 0 keeps
	// everything forever.
	AdvisoryEventRetentionMonths int
	RetentionPolicy              retention.RetentionPolicy
	Background                   BackgroundConfig
	AdvisoryScan                 AdvisoryScanConfig
	CVEFeed                      CVEFeedConfig
	KEV                          KEVConfig
	Worker                       WorkerConfig
	SecretScan                   SecretScanConfig

	Forges []ForgeConfig
}

type BackgroundConfig struct {
	ArtifactProcessingEnabled bool
	RetentionEnabled          bool
	StaleScanEnabled          bool
	StalePendingEnabled       bool
	// SecretScanEnabled defaults to false, unlike its siblings: the loop clones
	// repositories, so a single-replica install must opt in knowingly rather
	// than discover clone load on its API pod after an upgrade.
	SecretScanEnabled bool
}

type AdvisoryScanConfig struct {
	Providers []string
	Interval  time.Duration
}

// CVEFeedConfig configures the CVE Program feed sweep (ADR-028).
//
// The sweep always runs; there is no switch and no path to set. Its working
// directory is derived, because it holds nothing worth configuring: the resume
// point lives in the database, so the clone is a disposable ~10 MB cache that
// costs six seconds to rebuild.
type CVEFeedConfig struct {
	// Remote defaults to the public cvelistV5 repository.
	Remote string
	// Interval between sweeps. Polling much faster than the upstream commits
	// (~2.8 times an hour) only costs requests.
	Interval time.Duration
}

// KEVConfig configures the exploited-vulnerabilities catalog sync (ADR-032).
// CISA KEV and the ENISA EUVD exploited set are mirrored by default with
// nothing to configure — the Dependency-Track stance. Per-source toggles exist
// because the sync calls external services (cisa.gov, enisa.europa.eu), and an
// air-gapped instance with no mirror should be able to silence a failing
// source rather than carry a permanently red health entry.
type KEVConfig struct {
	// Enabled is the master switch, default true.
	Enabled bool
	// Interval between syncs, shared by all sources. Both catalogs update a
	// few times a week, so polling faster than hours only costs requests.
	Interval time.Duration
	CISA     KEVSourceConfig
	EUVD     KEVSourceConfig
}

// KEVSourceConfig is one catalog's switch and mirror override.
type KEVSourceConfig struct {
	// Enabled defaults to true.
	Enabled bool
	// URL defaults to the source's public endpoint; point it at a mirror
	// serving the same document/API for an instance with no outbound internet.
	URL string
}

type WorkerConfig struct {
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
}

type ArtifactS3Config struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	UsePathStyle    bool
	UseSSL          bool
}

type SecretScanConfig struct {
	Enabled   bool
	Providers []string
	TempDir   string
	OnPush    bool

	// Guardrails for a scanner that clones. Concurrency is per replica: scale by
	// adding workers, not goroutines, so disk and CPU stay bounded per pod.
	MaxConcurrency int
	// Timeout bounds a hung-but-alive gitleaks; the lease + heartbeat covers a
	// dead worker. Independent mechanisms, so Timeout may exceed LeaseDuration —
	// the heartbeat keeps extending the claim while work is genuinely running.
	Timeout     time.Duration
	MaxRepoMB   int
	MaxAttempts int
	// PollInterval is the idle backoff; a claimed job is followed immediately by
	// the next claim attempt.
	PollInterval time.Duration
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
	// Token is a forge API token the server authenticates its own calls with:
	// commit statuses, PR comments, repository reads. It is distinct from the
	// OAuth2 client credentials, which only authenticate a user login — a forge
	// rejects an API write made with them. GitHub App forges mint installation
	// tokens instead and leave this empty.
	Token string
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

// ParseEmailList splits a comma- or newline-separated email list, trimming
// and lowercasing entries so membership checks are case-insensitive. Shared
// with the file-based instance-admin list, which is re-read at check time.
func ParseEmailList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	emails := make([]string, 0, len(parts))
	for _, part := range parts {
		if email := strings.ToLower(strings.TrimSpace(part)); email != "" {
			emails = append(emails, email)
		}
	}
	return emails
}

func Load() (Config, error) {
	v := viper.New()

	v.SetEnvPrefix("HIBOU")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.SetDefault("host", "0.0.0.0")
	v.SetDefault("port", 8585)
	v.SetDefault("development", false)
	v.SetDefault("mcp.enabled", true)
	v.SetDefault("mcp.port", 8081)
	v.SetDefault("audit.retention_months", 0)
	v.SetDefault("base.url", "")
	v.SetDefault("database.url", "postgres://hibou:hibou@localhost:5432/hibou?sslmode=disable")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "console")
	v.SetDefault("trivy.url", "http://localhost:4954")
	v.SetDefault("osv.url", "https://api.osv.dev")
	v.SetDefault("cache.ttl", "6h")
	v.SetDefault("artifact.backend", "filesystem")
	v.SetDefault("artifact.path", "/data/artifacts")
	v.SetDefault("artifact.s3.endpoint", "")
	v.SetDefault("artifact.s3.region", "")
	v.SetDefault("artifact.s3.bucket", "")
	v.SetDefault("artifact.s3.access_key_id", "")
	v.SetDefault("artifact.s3.secret_access_key", "")
	v.SetDefault("artifact.s3.use_path_style", true)
	v.SetDefault("artifact.s3.use_ssl", true)
	v.SetDefault("upload.window", "10m")
	v.SetDefault("shutdown.timeout", "20s")
	v.SetDefault("max.upload.size", int64(104857600))
	v.SetDefault("session.secret", DefaultSessionSecret)
	v.SetDefault("auto.provision.orgs", false)
	v.SetDefault("instance.admins", "")
	v.SetDefault("instance.admins_file", "")
	v.SetDefault("coverage.store_lines", true)
	v.SetDefault("background.artifact_processing.enabled", true)
	v.SetDefault("background.retention.enabled", true)
	v.SetDefault("background.stale_scan.enabled", true)
	v.SetDefault("background.stale_pending.enabled", true)
	v.SetDefault("advisory_scan.providers", []string{"osv", "trivy"})
	v.SetDefault("advisory_scan.interval", "6h")
	v.SetDefault("cve_feed.remote", "")
	v.SetDefault("cve_feed.interval", "15m")
	v.SetDefault("kev.enabled", true)
	v.SetDefault("kev.interval", "6h")
	v.SetDefault("kev.cisa.enabled", true)
	v.SetDefault("kev.cisa.url", "")
	v.SetDefault("kev.euvd.enabled", true)
	v.SetDefault("kev.euvd.url", "")
	v.SetDefault("worker.lease.duration", "5m")
	v.SetDefault("worker.heartbeat.interval", "100s")
	v.SetDefault("retention.preset", "envelope")
	v.SetDefault("retention.auto_purge", false)
	v.SetDefault("background.secret_scan.enabled", false)
	v.SetDefault("secret_scan.enabled", false)
	v.SetDefault("secret_scan.providers", []string{})
	v.SetDefault("secret_scan.temp_dir", "")
	v.SetDefault("secret_scan.on_push", false)
	v.SetDefault("secret_scan.max_concurrency", 1)
	v.SetDefault("secret_scan.timeout", "5m")
	v.SetDefault("secret_scan.max_repo_mb", 2048)
	v.SetDefault("secret_scan.max_attempts", 3)
	v.SetDefault("secret_scan.poll_interval", "15s")

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
	shutdownTimeout, err := time.ParseDuration(v.GetString("shutdown.timeout"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing shutdown.timeout: %w", err)
	}
	if shutdownTimeout <= 0 {
		return Config{}, errors.New("parsing shutdown.timeout: duration must be greater than zero")
	}
	workerLeaseDuration, err := time.ParseDuration(v.GetString("worker.lease.duration"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing worker.lease.duration: %w", err)
	}
	if workerLeaseDuration <= 0 {
		return Config{}, errors.New("parsing worker.lease.duration: duration must be greater than zero")
	}
	workerHeartbeatInterval, err := time.ParseDuration(v.GetString("worker.heartbeat.interval"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing worker.heartbeat.interval: %w", err)
	}
	if workerHeartbeatInterval <= 0 {
		return Config{}, errors.New("parsing worker.heartbeat.interval: duration must be greater than zero")
	}
	if workerHeartbeatInterval >= workerLeaseDuration {
		return Config{}, errors.New("parsing worker heartbeat: worker.heartbeat.interval must be shorter than worker.lease.duration")
	}
	cveFeedInterval, err := time.ParseDuration(v.GetString("cve_feed.interval"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing cve_feed.interval: %w", err)
	}
	if cveFeedInterval <= 0 {
		return Config{}, errors.New("parsing cve_feed.interval: duration must be greater than zero")
	}
	kevInterval, err := time.ParseDuration(v.GetString("kev.interval"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing kev.interval: %w", err)
	}
	if kevInterval <= 0 {
		return Config{}, errors.New("parsing kev.interval: duration must be greater than zero")
	}

	advisoryScanInterval, err := time.ParseDuration(v.GetString("advisory_scan.interval"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing advisory_scan.interval: %w", err)
	}
	if advisoryScanInterval <= 0 {
		return Config{}, errors.New("parsing advisory_scan.interval: duration must be greater than zero")
	}
	secretScanTimeout, err := time.ParseDuration(v.GetString("secret_scan.timeout"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing secret_scan.timeout: %w", err)
	}
	if secretScanTimeout <= 0 {
		return Config{}, errors.New("parsing secret_scan.timeout: duration must be greater than zero")
	}
	secretScanPollInterval, err := time.ParseDuration(v.GetString("secret_scan.poll_interval"))
	if err != nil {
		return Config{}, fmt.Errorf("parsing secret_scan.poll_interval: %w", err)
	}
	if secretScanPollInterval <= 0 {
		return Config{}, errors.New("parsing secret_scan.poll_interval: duration must be greater than zero")
	}
	secretScanMaxConcurrency := v.GetInt("secret_scan.max_concurrency")
	if secretScanMaxConcurrency < 1 {
		return Config{}, errors.New("parsing secret_scan.max_concurrency: must be at least 1")
	}
	secretScanMaxAttempts := v.GetInt("secret_scan.max_attempts")
	if secretScanMaxAttempts < 1 || secretScanMaxAttempts > 100 {
		return Config{}, errors.New("parsing secret_scan.max_attempts: must be between 1 and 100")
	}
	retentionPolicy, err := loadRetentionPolicy(v)
	if err != nil {
		return Config{}, fmt.Errorf("parsing retention policy: %w", err)
	}

	cfg := Config{
		Host:            v.GetString("host"),
		Port:            v.GetInt("port"),
		Development:     v.GetBool("development"),
		MCPEnabled:      v.GetBool("mcp.enabled"),
		MCPPort:         v.GetInt("mcp.port"),
		BaseURL:         v.GetString("base.url"),
		DatabaseURL:     v.GetString("database.url"),
		LogLevel:        v.GetString("log.level"),
		LogFormat:       v.GetString("log.format"),
		TriviURL:        v.GetString("trivy.url"),
		OSVURL:          v.GetString("osv.url"),
		CacheTTL:        cacheTTL,
		ArtifactBackend: v.GetString("artifact.backend"),
		ArtifactPath:    v.GetString("artifact.path"),
		ArtifactS3: ArtifactS3Config{
			Endpoint:        strings.TrimSpace(v.GetString("artifact.s3.endpoint")),
			Region:          strings.TrimSpace(v.GetString("artifact.s3.region")),
			Bucket:          strings.TrimSpace(v.GetString("artifact.s3.bucket")),
			AccessKeyID:     strings.TrimSpace(v.GetString("artifact.s3.access_key_id")),
			SecretAccessKey: strings.TrimSpace(v.GetString("artifact.s3.secret_access_key")),
			UsePathStyle:    v.GetBool("artifact.s3.use_path_style"),
			UseSSL:          v.GetBool("artifact.s3.use_ssl"),
		},
		UploadWindow:                 uploadWindow,
		ShutdownTimeout:              shutdownTimeout,
		MaxUploadSize:                v.GetInt64("max.upload.size"),
		SessionSecret:                v.GetString("session.secret"),
		AutoProvisionOrgs:            v.GetBool("auto.provision.orgs"),
		InstanceAdmins:               ParseEmailList(v.GetString("instance.admins")),
		InstanceAdminsFile:           strings.TrimSpace(v.GetString("instance.admins_file")),
		CoverageStoreLines:           v.GetBool("coverage.store_lines"),
		AuditRetentionMonths:         v.GetInt("audit.retention_months"),
		AdvisoryEventRetentionMonths: v.GetInt("advisories.event_retention_months"),
		RetentionPolicy:              retentionPolicy,
		Background: BackgroundConfig{
			ArtifactProcessingEnabled: v.GetBool("background.artifact_processing.enabled"),
			RetentionEnabled:          v.GetBool("background.retention.enabled"),
			StaleScanEnabled:          v.GetBool("background.stale_scan.enabled"),
			StalePendingEnabled:       v.GetBool("background.stale_pending.enabled"),
			SecretScanEnabled:         v.GetBool("background.secret_scan.enabled"),
		},
		CVEFeed: CVEFeedConfig{
			Remote:   v.GetString("cve_feed.remote"),
			Interval: cveFeedInterval,
		},
		KEV: KEVConfig{
			Enabled:  v.GetBool("kev.enabled"),
			Interval: kevInterval,
			CISA: KEVSourceConfig{
				Enabled: v.GetBool("kev.cisa.enabled"),
				URL:     strings.TrimSpace(v.GetString("kev.cisa.url")),
			},
			EUVD: KEVSourceConfig{
				Enabled: v.GetBool("kev.euvd.enabled"),
				URL:     strings.TrimSpace(v.GetString("kev.euvd.url")),
			},
		},
		AdvisoryScan: AdvisoryScanConfig{
			Providers: normalizeProviderList(v.GetStringSlice("advisory_scan.providers")),
			Interval:  advisoryScanInterval,
		},
		Worker: WorkerConfig{
			LeaseDuration:     workerLeaseDuration,
			HeartbeatInterval: workerHeartbeatInterval,
		},
		SecretScan: SecretScanConfig{
			Enabled:        v.GetBool("secret_scan.enabled"),
			Providers:      normalizeList(v.GetStringSlice("secret_scan.providers")),
			TempDir:        strings.TrimSpace(v.GetString("secret_scan.temp_dir")),
			OnPush:         v.GetBool("secret_scan.on_push"),
			MaxConcurrency: secretScanMaxConcurrency,
			Timeout:        secretScanTimeout,
			MaxRepoMB:      v.GetInt("secret_scan.max_repo_mb"),
			MaxAttempts:    secretScanMaxAttempts,
			PollInterval:   secretScanPollInterval,
		},
	}

	cfg.Forges = loadForgeConfigs()
	return cfg, nil
}

func normalizeProviderList(values []string) []string {
	providers := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			provider := strings.ToLower(strings.TrimSpace(part))
			if provider == "" {
				continue
			}
			if _, ok := seen[provider]; ok {
				continue
			}
			seen[provider] = struct{}{}
			providers = append(providers, provider)
		}
	}
	return providers
}

func (c Config) IsDevelopment() bool {
	return c.Development
}

func (c Config) ValidateStartup(log zerolog.Logger) error {
	secret := strings.TrimSpace(c.SessionSecret)
	if secret != "" && secret != DefaultSessionSecret {
		return nil
	}

	if c.IsDevelopment() {
		log.Warn().Msg("HIBOU_SESSION_SECRET is empty or using the default development signing secret; replace it with a stable shared secret before any production or multi-replica deployment because rotating it invalidates existing hibou_session and hibou_oauth_state cookies")
		return nil
	}

	return errors.New("invalid session.secret: set HIBOU_SESSION_SECRET/session.secret to a stable random value shared by every replica; empty values and the shipped development default are rejected unless HIBOU_DEVELOPMENT/development is explicitly set for local development")
}

func loadRetentionPolicy(v *viper.Viper) (retention.RetentionPolicy, error) {
	overrides := retention.PolicyOverrides{}

	if duration, ok, err := durationOverride(v, "retention.keep_all"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.KeepAll = &duration
	}
	if budget, ok, err := bytesOverride(v, "retention.storage.budget"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Storage.Budget = &budget
	}
	if warnAt, ok, err := ratioOverride(v, "retention.storage.warn_at"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Storage.WarnAt = &warnAt
	}
	if target, ok, err := ratioOverride(v, "retention.storage.target"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Storage.Target = &target
	}
	if order, ok, err := evictOrderOverride(v, "retention.storage.evict_order"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Storage.EvictOrder = &order
	}
	if enabled, ok := boolOverride(v, "retention.tiers.enabled"); ok {
		overrides.Tiers.Enabled = &enabled
	}
	if anchor, ok, err := weekdayOverride(v, "retention.tiers.week_anchor"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Tiers.WeekAnchor = &anchor
	}
	if rep, ok, err := representativeOverride(v, "retention.tiers.representative"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Tiers.Representative = &rep
	}
	if keep, ok, err := intOverride(v, "retention.tiers.daily.keep"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Tiers.DailyKeep = &keep
	}
	if keep, ok, err := intOverride(v, "retention.tiers.weekly.keep"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Tiers.WeeklyKeep = &keep
	}
	if keep, ok, err := intOverride(v, "retention.tiers.monthly.keep"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Tiers.MonthlyKeep = &keep
	}
	if keep, ok, err := intOverride(v, "retention.tiers.yearly.keep"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.Tiers.YearlyKeep = &keep
	}
	if action, ok, err := thinActionOverride(v, "retention.on_thin.artifacts"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.OnThin.Artifacts = &action
	}
	if action, ok, err := thinActionOverride(v, "retention.on_thin.summary"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.OnThin.Summary = &action
	}
	if enabled, ok := boolOverride(v, "retention.pin.tags"); ok {
		overrides.Pin.Tags = &enabled
	}
	if enabled, ok := boolOverride(v, "retention.pin.latest_per_ref"); ok {
		overrides.Pin.LatestPerRef = &enabled
	}
	if enabled, ok := boolOverride(v, "retention.pin.referenced_by_open_findings"); ok {
		overrides.Pin.ReferencedByOpenFindings = &enabled
	}
	if labels, ok := stringSliceOverride(v, "retention.pin.labels"); ok {
		overrides.Pin.Labels = &labels
	} else if labels, ok := stringSliceOverride(v, "retention.pin.labeled"); ok {
		overrides.Pin.Labels = &labels
	}
	if duration, ok, err := durationOverride(v, "retention.pr.keep_all"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.PRSnapshots.KeepAll = &duration
	} else if duration, ok, err := durationOverride(v, "retention.pr_snapshots.keep_all"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.PRSnapshots.KeepAll = &duration
	}
	if action, ok, err := thinActionOverride(v, "retention.pr.after_close"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.PRSnapshots.AfterClose = &action
	} else if action, ok, err := thinActionOverride(v, "retention.pr_snapshots.after_close"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.PRSnapshots.AfterClose = &action
	}
	if duration, ok, err := durationOverride(v, "retention.failed_retention"); err != nil {
		return retention.RetentionPolicy{}, err
	} else if ok {
		overrides.FailedRetention = &duration
	}
	if enabled, ok := boolOverride(v, "retention.auto_purge"); ok {
		overrides.AutoPurge = &enabled
	}
	if enabled, ok := boolOverride(v, "retention.dry_run"); ok {
		overrides.DryRun = &enabled
	}

	return retention.Resolve(v.GetString("retention.preset"), overrides), nil
}

func durationOverride(v *viper.Viper, key string) (time.Duration, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return 0, false, nil
	}
	parsed, err := parseRetentionDuration(raw)
	if err != nil {
		return 0, false, err
	}
	return parsed, true, nil
}

func bytesOverride(v *viper.Viper, key string) (int64, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return 0, false, nil
	}
	parsed, err := parseByteSize(raw)
	if err != nil {
		return 0, false, err
	}
	return parsed, true, nil
}

func ratioOverride(v *viper.Viper, key string) (float64, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return 0, false, nil
	}
	parsed, err := parseRatio(raw)
	if err != nil {
		return 0, false, err
	}
	return parsed, true, nil
}

func evictOrderOverride(v *viper.Viper, key string) (retention.EvictOrder, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return "", false, nil
	}
	parsed := retention.EvictOrder(raw)
	switch parsed {
	case retention.EvictSpread, retention.EvictOldest, retention.EvictWorstFirst:
		return parsed, true, nil
	default:
		return "", false, fmt.Errorf("invalid evict order %q", raw)
	}
}

func representativeOverride(v *viper.Viper, key string) (retention.RepresentativeChoice, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return "", false, nil
	}
	parsed := retention.RepresentativeChoice(raw)
	switch parsed {
	case retention.RepresentativeLast, retention.RepresentativeFirst, retention.RepresentativeWorst:
		return parsed, true, nil
	default:
		return "", false, fmt.Errorf("invalid representative %q", raw)
	}
}

func weekdayOverride(v *viper.Viper, key string) (time.Weekday, bool, error) {
	raw := strings.ToLower(strings.TrimSpace(v.GetString(key)))
	if raw == "" {
		return 0, false, nil
	}
	weekdays := map[string]time.Weekday{
		"sunday":    time.Sunday,
		"monday":    time.Monday,
		"tuesday":   time.Tuesday,
		"wednesday": time.Wednesday,
		"thursday":  time.Thursday,
		"friday":    time.Friday,
		"saturday":  time.Saturday,
	}
	weekday, ok := weekdays[raw]
	if !ok {
		return 0, false, fmt.Errorf("invalid week anchor %q", raw)
	}
	return weekday, true, nil
}

func thinActionOverride(v *viper.Viper, key string) (retention.ThinAction, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return "", false, nil
	}
	parsed := retention.ThinAction(raw)
	switch parsed {
	case retention.ThinKeep, retention.ThinPurge:
		return parsed, true, nil
	default:
		return "", false, fmt.Errorf("invalid thin action %q", raw)
	}
}

func intOverride(v *viper.Viper, key string) (int, bool, error) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return 0, false, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false, err
	}
	return parsed, true, nil
}

func boolOverride(v *viper.Viper, key string) (bool, bool) {
	raw := strings.TrimSpace(v.GetString(key))
	if raw == "" {
		return false, false
	}
	return v.GetBool(key), true
}

func stringSliceOverride(v *viper.Viper, key string) ([]string, bool) {
	values := normalizeList(v.GetStringSlice(key))
	if len(values) == 0 {
		return nil, false
	}
	return values, true
}

func parseByteSize(value string) (int64, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(value))
	multiplier := int64(1)
	for suffix, candidate := range map[string]int64{"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40} {
		if strings.HasSuffix(trimmed, suffix) {
			multiplier = candidate
			trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, suffix))
			break
		}
	}
	parsed, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, err
	}
	return int64(parsed * float64(multiplier)), nil
}

func parseRatio(value string) (float64, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasSuffix(trimmed, "%") {
		parsed, err := strconv.ParseFloat(strings.TrimSuffix(trimmed, "%"), 64)
		if err != nil {
			return 0, err
		}
		return parsed / 100, nil
	}
	return strconv.ParseFloat(trimmed, 64)
}

func parseRetentionDuration(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasSuffix(strings.ToLower(trimmed), "d") {
		days, err := strconv.ParseFloat(strings.TrimSpace(trimmed[:len(trimmed)-1]), 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(trimmed)
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
//	HIBOU_FORGE_0_TOKEN=jkl
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
			Token:         strings.TrimSpace(os.Getenv(prefix + "TOKEN")),
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
