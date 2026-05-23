package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/hibouhq/lehibou/internal/auth"
	"github.com/hibouhq/lehibou/internal/config"
	"github.com/hibouhq/lehibou/internal/forge"
	"github.com/hibouhq/lehibou/internal/rbac"
	"github.com/hibouhq/lehibou/internal/server"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/ui"
)

var skipMigrations bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server, SPA, workers, and MCP endpoint",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		log := newLogger(cfg)

		db, err := store.New(cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connecting database: %w", err)
		}
		defer func() {
			_ = db.Close()
		}()

		if skipMigrations {
			log.Info().Msg("database migrations skipped")
		} else {
			if err := store.Migrate(db); err != nil {
				return fmt.Errorf("migrating database: %w", err)
			}
			log.Info().Msg("database migrations applied")
		}

		siteFS := ui.FS()
		if siteFS != nil {
			log.Info().Msg("embedded SPA detected, serving frontend")
		} else {
			log.Warn().Msg("no embedded SPA found, API-only mode")
		}

		enforcer, err := rbac.New(db)
		if err != nil {
			return fmt.Errorf("creating rbac enforcer: %w", err)
		}

		forges := make(map[string]forge.Provider)
		for _, fc := range cfg.Forges {
			if fc.ClientID == "" {
				continue
			}
			switch fc.Type {
			case "github":
				forges[fc.ID] = forge.NewGitHub(fc.ClientID, fc.ClientSecret, fc.WebhookSecret)
			case "forgejo", "gitea":
				forges[fc.ID] = forge.NewForgejo(fc.URL, fc.ClientID, fc.ClientSecret, fc.WebhookSecret)
			case "gitlab":
				forges[fc.ID] = forge.NewGitLab(fc.URL, fc.ClientID, fc.ClientSecret, fc.WebhookSecret)
			default:
				log.Warn().Str("type", fc.Type).Str("id", fc.ID).Msg("unknown forge type, skipping")
			}
		}

		authMgr := auth.New(auth.Config{
			SessionSecret: cfg.SessionSecret,
			CookieDomain:  cfg.Host,
			CookieSecure:  cfg.Host != "0.0.0.0" && cfg.Host != "localhost",
			Providers:     forges,
		}, store.NewQueries(db))

		srv := server.New(cfg, log, db, enforcer, authMgr, forges, siteFS)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return srv.ListenAndServe(ctx)
	},
}

func newLogger(cfg config.Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	if cfg.LogFormat == "json" {
		return zerolog.New(os.Stdout).Level(level).With().Timestamp().Logger()
	}

	return zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}).Level(level).With().Timestamp().Logger()
}

func init() {
	serveCmd.Flags().BoolVar(&skipMigrations, "skip-migrations", false, "skip database migrations on startup")
	rootCmd.AddCommand(serveCmd)
}
