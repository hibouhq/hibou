package config

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func TestForgeEventModeValidation(t *testing.T) {
	log := zerolog.New(io.Discard)
	for _, test := range []struct {
		name, mode, kind, secret string
		app                      bool
		valid                    bool
	}{
		{"default", "", "github", "signed", false, true},
		{"poll", "poll", "github", "", true, true},
		{"poll still disables configured secret", "poll", "github", "unused", true, true},
		{"hybrid", "hybrid", "github", "signed", true, true},
		{"hybrid missing secret", "hybrid", "github", "", true, false},
		{"default missing secret", "", "github", "", true, false},
		{"unknown", "typo", "github", "signed", true, false},
		{"unsupported", "poll", "gitlab", "", true, false},
		{"no app", "poll", "github", "", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fc := ForgeConfig{ID: "test", Type: test.kind, EventMode: test.mode, WebhookSecret: test.secret, ClientID: "oauth"}
			if test.app {
				fc.AppID = 1
				fc.PrivateKey = "key"
			}
			err := (Config{Forges: []ForgeConfig{fc}}).validateForges(log)
			if (err == nil) != test.valid {
				t.Fatalf("validation=%v, want valid=%v", err, test.valid)
			}
		})
	}
}

func TestForgeEventYAMLAndEnv(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`forges:
  - type: github
    id: enterprise
    event_mode: poll
    poll_interval: 30s
    inventory_interval: 2m
    client_id: oauth
    app_id: 7
    private_key: key
`)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HIBOU_FORGE_0_POLL_INTERVAL", "45s")
	fc, err := loadForgeConfigs(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(fc) != 1 || fc[0].PollInterval != 45*time.Second || fc[0].InventoryInterval != 2*time.Minute || fc[0].ClientID != "oauth" || fc[0].AppID != 7 {
		t.Fatalf("configuration=%+v", fc)
	}
	t.Setenv("HIBOU_FORGE_0_POLL_INTERVAL", "0s")
	if _, err := loadForgeConfigs(v); err == nil {
		t.Fatal("zero interval accepted")
	}
	t.Setenv("HIBOU_FORGE_0_POLL_INTERVAL", "bad")
	if _, err := loadForgeConfigs(v); err == nil {
		t.Fatal("invalid duration accepted")
	}
	v.Set("forges", []map[string]any{{"type": "github", "poll_interval": "0s"}})
	if err := os.Unsetenv("HIBOU_FORGE_0_POLL_INTERVAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadForgeConfigs(v); err == nil {
		t.Fatal("zero YAML interval accepted")
	}
}
