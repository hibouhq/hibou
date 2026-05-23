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
