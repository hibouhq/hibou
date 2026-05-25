package cliconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds CLI-side configuration stored on disk.
type Config struct {
	Server string `yaml:"server,omitempty"`
	Token  string `yaml:"token,omitempty"`
	Org    string `yaml:"org,omitempty"`
}

// DefaultPath returns ~/.config/hibou/config.yaml.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "hibou", "config.yaml")
}

// Load reads the config file. Returns zero-value Config if file doesn't exist.
func Load() (Config, error) {
	data, err := os.ReadFile(DefaultPath())
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to disk, creating directories as needed.
func Save(cfg Config) error {
	path := DefaultPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}
