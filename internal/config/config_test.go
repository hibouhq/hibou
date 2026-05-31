package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 8585 {
		t.Errorf("expected default port 8585, got %d", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.ListenAddr() != "0.0.0.0:8585" {
		t.Errorf("expected listen addr 0.0.0.0:8585, got %s", cfg.ListenAddr())
	}
	if cfg.OSVURL != "https://api.osv.dev" {
		t.Errorf("expected default OSV URL, got %s", cfg.OSVURL)
	}
	if cfg.CacheTTL != 6*time.Hour {
		t.Errorf("expected default cache ttl 6h, got %s", cfg.CacheTTL)
	}
	if cfg.ArtifactPath != "/data/artifacts" {
		t.Errorf("expected default artifact path /data/artifacts, got %s", cfg.ArtifactPath)
	}
	if cfg.SecretScan.Enabled {
		t.Fatal("expected secret scanning disabled by default")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("HIBOU_PORT", "9090")
	t.Setenv("HIBOU_HOST", "127.0.0.1")
	t.Setenv("HIBOU_LOG_LEVEL", "debug")
	t.Setenv("HIBOU_OSV_URL", "http://osv.internal")
	t.Setenv("HIBOU_CACHE_TTL", "30m")
	t.Setenv("HIBOU_ARTIFACT_PATH", "/tmp/hibou-artifacts")
	t.Setenv("HIBOU_SECRET_SCAN_ENABLED", "true")
	t.Setenv("HIBOU_SECRET_SCAN_PROVIDERS", "gitleaks,github")
	t.Setenv("HIBOU_SECRET_SCAN_TEMP_DIR", "/tmp/hibou-secrets")
	t.Setenv("HIBOU_SECRET_SCAN_ON_PUSH", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Port)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Host)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.LogLevel)
	}
	if cfg.OSVURL != "http://osv.internal" {
		t.Errorf("expected OSV URL override, got %s", cfg.OSVURL)
	}
	if cfg.CacheTTL != 30*time.Minute {
		t.Errorf("expected cache ttl override, got %s", cfg.CacheTTL)
	}
	if cfg.ArtifactPath != "/tmp/hibou-artifacts" {
		t.Errorf("expected artifact path override, got %s", cfg.ArtifactPath)
	}
	if !cfg.SecretScan.Enabled {
		t.Fatal("expected secret scan enabled from env")
	}
	if got := len(cfg.SecretScan.Providers); got != 2 {
		t.Fatalf("expected 2 secret scan providers, got %d", got)
	}
	if cfg.SecretScan.TempDir != "/tmp/hibou-secrets" {
		t.Fatalf("expected secret scan temp dir override, got %s", cfg.SecretScan.TempDir)
	}
	if !cfg.SecretScan.OnPush {
		t.Fatal("expected secret scan on_push enabled")
	}

	// Clean up is handled by t.Setenv automatically
	_ = os.Getenv("HIBOU_PORT") // suppress unused import
}

func TestLoadForgeConfigs(t *testing.T) {
	t.Setenv("HIBOU_FORGE_0_TYPE", "forgejo")
	t.Setenv("HIBOU_FORGE_0_ID", "dev-forgejo")
	t.Setenv("HIBOU_FORGE_0_URL", "http://localhost:3030")
	t.Setenv("HIBOU_FORGE_0_CLIENT_ID", "client-0")
	t.Setenv("HIBOU_FORGE_0_CLIENT_SECRET", "secret-0")
	t.Setenv("HIBOU_FORGE_0_WEBHOOK_SECRET", "hook-0")
	t.Setenv("HIBOU_FORGE_0_IP_ALLOWLIST", "true")
	t.Setenv("HIBOU_FORGE_0_RATE_LIMIT_RPS", "7.5")

	t.Setenv("HIBOU_FORGE_1_TYPE", "github")
	t.Setenv("HIBOU_FORGE_1_CLIENT_ID", "client-1")
	t.Setenv("HIBOU_FORGE_1_CLIENT_SECRET", "secret-1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.Forges) != 2 {
		t.Fatalf("expected 2 forge configs, got %d", len(cfg.Forges))
	}

	f0 := cfg.Forges[0]
	if f0.Type != "forgejo" {
		t.Errorf("forge 0: expected type forgejo, got %s", f0.Type)
	}
	if f0.ID != "dev-forgejo" {
		t.Errorf("forge 0: expected id dev-forgejo, got %s", f0.ID)
	}
	if f0.URL != "http://localhost:3030" {
		t.Errorf("forge 0: expected url http://localhost:3030, got %s", f0.URL)
	}
	if f0.ClientID != "client-0" {
		t.Errorf("forge 0: expected client_id client-0, got %s", f0.ClientID)
	}
	if !f0.IPAllowlist {
		t.Error("forge 0: expected ip allowlist enabled")
	}
	if f0.RateLimitRPS != 7.5 {
		t.Errorf("forge 0: expected rate limit 7.5, got %v", f0.RateLimitRPS)
	}

	f1 := cfg.Forges[1]
	if f1.Type != "github" {
		t.Errorf("forge 1: expected type github, got %s", f1.Type)
	}
	if f1.ID != "github" {
		t.Errorf("forge 1: expected default id github, got %s", f1.ID)
	}
}

func TestLoadForgeConfigsEmpty(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.Forges) != 0 {
		t.Errorf("expected 0 forge configs without env vars, got %d", len(cfg.Forges))
	}
}

func TestLoadFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	configContent := `
host: 10.0.0.1
port: 9999
log:
  level: trace
cache:
  ttl: "1h"
`

	err := os.WriteFile(filepath.Join(dir, "hibou-server.yaml"), []byte(configContent), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(originalDir); chdirErr != nil {
			t.Fatalf("restoring working directory: %v", chdirErr)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Host != "10.0.0.1" {
		t.Errorf("expected host from file, got %s", cfg.Host)
	}
	if cfg.Port != 9999 {
		t.Errorf("expected port from file, got %d", cfg.Port)
	}
	if cfg.LogLevel != "trace" {
		t.Errorf("expected log level from file, got %s", cfg.LogLevel)
	}
}

func TestEnvOverridesConfigFile(t *testing.T) {
	dir := t.TempDir()
	configContent := `
port: 7777
`

	err := os.WriteFile(filepath.Join(dir, "hibou-server.yaml"), []byte(configContent), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(originalDir); chdirErr != nil {
			t.Fatalf("restoring working directory: %v", chdirErr)
		}
	}()

	t.Setenv("HIBOU_PORT", "8888")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 8888 {
		t.Errorf("expected env to override file, got %d", cfg.Port)
	}
}
