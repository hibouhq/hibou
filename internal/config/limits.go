package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// LimitsConfig bounds what one client can make the server spend: connections,
// request time, body sizes, request rates and upload concurrency. Every value
// has a working default; zero or negative values are rejected at load, except
// where a field documents that zero disables it.
type LimitsConfig struct {
	DB        DBPoolConfig
	HTTP      HTTPLimitsConfig
	RateLimit RateLimitConfig
	Upload    UploadLimitsConfig
}

// DBPoolConfig sizes the server's Postgres pool. Session timeouts
// (statement_timeout, idle_in_transaction_session_timeout) default in
// store.New and are overridden through the database URL.
type DBPoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

type HTTPLimitsConfig struct {
	// ReadTimeout covers reading a whole request, body included.
	ReadTimeout time.Duration
	// UploadReadTimeout replaces ReadTimeout on POST /upload, whose body is
	// up to max.upload.size.
	UploadReadTimeout time.Duration
	// WriteTimeout covers handler time plus writing the response. Websockets
	// and file downloads clear it per route.
	WriteTimeout time.Duration
	// RequestTimeout cancels the context of ordinary API requests. Uploads,
	// websockets, webhooks, downloads and the push check are exempt.
	RequestTimeout time.Duration
	MaxHeaderBytes int
	// MaxBodyBytes is the default request body cap; routes that take more
	// (uploads, webhooks, SBOM compare) raise it explicitly.
	MaxBodyBytes        int64
	WebhookMaxBodyBytes int64
}

// RateLimitConfig is a token bucket per principal (API key, else user, else
// client IP) on the authenticated API, and per client IP on /auth/* and other
// anonymous routes. RPS is the refill rate, Burst the bucket size.
type RateLimitConfig struct {
	Enabled   bool
	API       RateLimitBucket
	Upload    RateLimitBucket
	Scan      RateLimitBucket
	Auth      RateLimitBucket
	Anonymous RateLimitBucket
}

type RateLimitBucket struct {
	RPS   float64
	Burst int
}

type UploadLimitsConfig struct {
	// MaxConcurrent uploads are processed at once per replica; others wait up
	// to QueueWait, then get 503 with Retry-After.
	MaxConcurrent int
	QueueWait     time.Duration
	// MaxItems caps SARIF results, SBOM components/packages, VEX statements
	// and test cases in one artifact (422 above it).
	MaxItems int
	// ProcessingConcurrency bounds the background coverage/test parsers.
	ProcessingConcurrency int
}

func setLimitsDefaults(v *viper.Viper) {
	v.SetDefault("db.max_open_conns", 40)
	v.SetDefault("db.max_idle_conns", 10)
	v.SetDefault("db.conn_max_lifetime", "30m")
	v.SetDefault("db.conn_max_idle_time", "5m")
	v.SetDefault("http.read_timeout", "5m")
	v.SetDefault("http.upload_read_timeout", "15m")
	v.SetDefault("http.write_timeout", "10m")
	v.SetDefault("http.request_timeout", "60s")
	v.SetDefault("http.max_header_bytes", 64<<10)
	v.SetDefault("http.max_body_bytes", int64(1<<20))
	v.SetDefault("http.webhook_max_body_bytes", int64(25<<20))
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.api.rps", 20.0)
	v.SetDefault("rate_limit.api.burst", 200)
	v.SetDefault("rate_limit.upload.rps", 2.0)
	v.SetDefault("rate_limit.upload.burst", 60)
	v.SetDefault("rate_limit.scan.rps", 0.1)
	v.SetDefault("rate_limit.scan.burst", 5)
	v.SetDefault("rate_limit.auth.rps", 1.0)
	v.SetDefault("rate_limit.auth.burst", 30)
	v.SetDefault("rate_limit.anonymous.rps", 10.0)
	v.SetDefault("rate_limit.anonymous.burst", 100)
	v.SetDefault("upload.max_concurrent", 3)
	v.SetDefault("upload.queue_wait", "30s")
	v.SetDefault("upload.max_items", 200000)
	v.SetDefault("upload.processing_concurrency", 2)
}

func loadLimits(v *viper.Viper) (LimitsConfig, error) {
	setLimitsDefaults(v)
	durations := map[string]*time.Duration{}
	var cfg LimitsConfig
	durations["db.conn_max_lifetime"] = &cfg.DB.ConnMaxLifetime
	durations["db.conn_max_idle_time"] = &cfg.DB.ConnMaxIdleTime
	durations["http.read_timeout"] = &cfg.HTTP.ReadTimeout
	durations["http.upload_read_timeout"] = &cfg.HTTP.UploadReadTimeout
	durations["http.write_timeout"] = &cfg.HTTP.WriteTimeout
	durations["http.request_timeout"] = &cfg.HTTP.RequestTimeout
	durations["upload.queue_wait"] = &cfg.Upload.QueueWait
	for key, target := range durations {
		parsed, err := time.ParseDuration(v.GetString(key))
		if err != nil {
			return LimitsConfig{}, fmt.Errorf("parsing %s: %w", key, err)
		}
		if parsed <= 0 {
			return LimitsConfig{}, fmt.Errorf("parsing %s: duration must be greater than zero", key)
		}
		*target = parsed
	}

	cfg.DB.MaxOpenConns = v.GetInt("db.max_open_conns")
	cfg.DB.MaxIdleConns = v.GetInt("db.max_idle_conns")
	cfg.HTTP.MaxHeaderBytes = v.GetInt("http.max_header_bytes")
	cfg.HTTP.MaxBodyBytes = v.GetInt64("http.max_body_bytes")
	cfg.HTTP.WebhookMaxBodyBytes = v.GetInt64("http.webhook_max_body_bytes")
	cfg.Upload.MaxConcurrent = v.GetInt("upload.max_concurrent")
	cfg.Upload.MaxItems = v.GetInt("upload.max_items")
	cfg.Upload.ProcessingConcurrency = v.GetInt("upload.processing_concurrency")
	for key, value := range map[string]int64{
		"db.max_open_conns":             int64(cfg.DB.MaxOpenConns),
		"db.max_idle_conns":             int64(cfg.DB.MaxIdleConns),
		"http.max_header_bytes":         int64(cfg.HTTP.MaxHeaderBytes),
		"http.max_body_bytes":           cfg.HTTP.MaxBodyBytes,
		"http.webhook_max_body_bytes":   cfg.HTTP.WebhookMaxBodyBytes,
		"upload.max_concurrent":         int64(cfg.Upload.MaxConcurrent),
		"upload.max_items":              int64(cfg.Upload.MaxItems),
		"upload.processing_concurrency": int64(cfg.Upload.ProcessingConcurrency),
	} {
		if value < 1 {
			return LimitsConfig{}, fmt.Errorf("parsing %s: must be at least 1", key)
		}
	}

	cfg.RateLimit.Enabled = v.GetBool("rate_limit.enabled")
	buckets := map[string]*RateLimitBucket{
		"api":       &cfg.RateLimit.API,
		"upload":    &cfg.RateLimit.Upload,
		"scan":      &cfg.RateLimit.Scan,
		"auth":      &cfg.RateLimit.Auth,
		"anonymous": &cfg.RateLimit.Anonymous,
	}
	for name, bucket := range buckets {
		bucket.RPS = v.GetFloat64("rate_limit." + name + ".rps")
		bucket.Burst = v.GetInt("rate_limit." + name + ".burst")
		if cfg.RateLimit.Enabled && (bucket.RPS <= 0 || bucket.Burst < 1) {
			return LimitsConfig{}, errors.New("parsing rate_limit." + name + ": rps must be > 0 and burst >= 1 (set rate_limit.enabled=false to disable)")
		}
	}
	return cfg, nil
}

// DefaultLimits returns the limits a fresh install loads with.
func DefaultLimits() LimitsConfig {
	cfg, err := loadLimits(viper.New())
	if err != nil {
		panic(fmt.Sprintf("default limits do not load: %v", err))
	}
	return cfg
}
