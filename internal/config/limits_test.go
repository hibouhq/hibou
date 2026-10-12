package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLoadLimitsDefaults(t *testing.T) {
	cfg, err := loadLimits(viper.New())
	if err != nil {
		t.Fatalf("loadLimits: %v", err)
	}
	if cfg.DB.MaxOpenConns != 40 || cfg.HTTP.ReadTimeout != 5*time.Minute || cfg.HTTP.MaxBodyBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if !cfg.RateLimit.Enabled || cfg.RateLimit.Upload.Burst < 1 || cfg.Upload.MaxConcurrent != 3 || cfg.Upload.MaxItems != 200000 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadLimitsRejectsNonPositive(t *testing.T) {
	for key, value := range map[string]any{
		"upload.max_concurrent": 0,
		"http.request_timeout":  "0s",
		"rate_limit.api.rps":    0.0,
	} {
		v := viper.New()
		v.Set(key, value)
		if _, err := loadLimits(v); err == nil || !strings.Contains(err.Error(), strings.Split(key, ".")[0]) {
			t.Fatalf("%s=%v: err = %v, want a rejection", key, value, err)
		}
	}
	// Disabling rate limiting makes the bucket values irrelevant.
	v := viper.New()
	v.Set("rate_limit.enabled", false)
	v.Set("rate_limit.api.rps", 0.0)
	if _, err := loadLimits(v); err != nil {
		t.Fatalf("disabled rate limit: %v", err)
	}
}
