package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.ListenAddr() != "0.0.0.0:8080" {
		t.Errorf("expected listen addr 0.0.0.0:8080, got %s", cfg.ListenAddr())
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("HIBOU_PORT", "9090")
	t.Setenv("HIBOU_HOST", "127.0.0.1")
	t.Setenv("HIBOU_LOG_LEVEL", "debug")

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

	// Clean up is handled by t.Setenv automatically
	_ = os.Getenv("HIBOU_PORT") // suppress unused import
}

func TestLoadForgeConfigs(t *testing.T) {
	t.Setenv("HIBOU_FORGE_0_TYPE", "forgejo")
	t.Setenv("HIBOU_FORGE_0_ID", "dev-forgejo")
	t.Setenv("HIBOU_FORGE_0_URL", "http://localhost:3000")
	t.Setenv("HIBOU_FORGE_0_CLIENT_ID", "client-0")
	t.Setenv("HIBOU_FORGE_0_CLIENT_SECRET", "secret-0")
	t.Setenv("HIBOU_FORGE_0_WEBHOOK_SECRET", "hook-0")

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
	if f0.URL != "http://localhost:3000" {
		t.Errorf("forge 0: expected url http://localhost:3000, got %s", f0.URL)
	}
	if f0.ClientID != "client-0" {
		t.Errorf("forge 0: expected client_id client-0, got %s", f0.ClientID)
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
