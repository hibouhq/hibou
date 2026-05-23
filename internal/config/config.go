// Package config provides environment-based configuration for the hibou server.
package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	Host         string `env:"HIBOU_HOST"          envDefault:"0.0.0.0"`
	Port         int    `env:"HIBOU_PORT"          envDefault:"8080"`
	DatabaseURL  string `env:"HIBOU_DATABASE_URL"  envDefault:"postgres://hibou:hibou@localhost:5432/hibou?sslmode=disable"`
	LogLevel     string `env:"HIBOU_LOG_LEVEL"     envDefault:"info"`
	LogFormat    string `env:"HIBOU_LOG_FORMAT"    envDefault:"console"`
	TriviURL     string `env:"HIBOU_TRIVY_URL"     envDefault:"http://localhost:4954"`
}

func (c Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func Load() (Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}
