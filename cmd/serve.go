package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/forge"
	hiboumcp "github.com/hibouhq/hibou/internal/mcp"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/server"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ui"
	"github.com/hibouhq/hibou/internal/version"
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
		if err := cfg.ValidateStartup(log); err != nil {
			return err
		}
		if err := cfg.ValidateServe(log); err != nil {
			return err
		}

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
				// ValidateStartup refuses this outside development.
				log.Warn().Str("id", fc.ID).Msg("forge has no OAuth client id, skipping (development only)")
				continue
			}
			switch fc.Type {
			case "github":
				var opts []forge.GitHubOption
				if fc.AppID > 0 && fc.PrivateKey != "" {
					opts = append(opts, forge.WithAppCredentials(fc.AppID, []byte(fc.PrivateKey)))
				}
				if len(cfg.Auth.AllowedOrgs) > 0 {
					// Only takes effect without App credentials (OAuth App
					// login): App mode checks membership with the
					// installation token instead.
					opts = append(opts, forge.WithOrgMembershipScope())
				}
				forges[fc.ID] = forge.NewGitHub(fc.ClientID, fc.ClientSecret, fc.WebhookSecret, opts...)
			case "forgejo", "gitea":
				forges[fc.ID] = forge.NewForgejo(fc.URL, fc.ClientID, fc.ClientSecret, fc.WebhookSecret, fc.Token)
			case "gitlab":
				forges[fc.ID] = forge.NewGitLab(fc.URL, fc.ClientID, fc.ClientSecret, fc.WebhookSecret)
			default:
				log.Warn().Str("type", fc.Type).Str("id", fc.ID).Msg("unknown forge type, skipping")
			}
		}

		queries := store.NewQueries(db)

		authMgr := auth.New(auth.Config{
			SessionSecret: cfg.SessionSecret,
			BaseURL:       cfg.BaseURL,
			CookieSecure:  cfg.CookieSecure(),
			Providers:     forges,
			Development:   cfg.IsDevelopment(),
			AllowedOrgs:   cfg.Auth.AllowedOrgs,
			AllowedUsers:  cfg.Auth.AllowedUsers,
			Log:           log,
		}, queries)
		if cfg.Auth.Restricted() {
			log.Info().Strs("allowed_orgs", cfg.Auth.AllowedOrgs).Int("allowed_users", len(cfg.Auth.AllowedUsers)).Msg("sign-in restricted by allowlist")
		}

		srv, err := server.New(cfg, log, db, enforcer, authMgr, forges, siteFS)
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		services := 1
		errCh := make(chan error, 2)

		go func() {
			errCh <- srv.ListenAndServe(ctx)
		}()

		switch {
		case !cfg.Metrics.Enabled:
			// metrics.enabled=false: /metrics is served on no listener.
		case cfg.Metrics.Port != 0:
			metricsMux := http.NewServeMux()
			metricsMux.Handle("/metrics", srv.MetricsHandler())
			metricsHTTP := &metricsServer{&http.Server{Handler: metricsMux, ReadHeaderTimeout: 10 * time.Second}}
			services++
			go func() {
				errCh <- runAuxServer(ctx, "metrics", metricsHTTP, cfg.MetricsListenAddr(), cfg.ShutdownTimeout, log)
			}()
		}

		if cfg.MCPEnabled {
			mcpDelta := delta.NewService(delta.NewStoreAdapter(queries), log)
			var mcpOptions []hiboumcp.Option
			if policy := srv.PackagePolicy(); policy != nil {
				mcpOptions = append(mcpOptions, hiboumcp.WithPackagePolicy(policy))
			}
			mcpSrv := hiboumcp.New(queries, mcpDelta, log, version.Version, mcpOptions...)
			// The sign-in allowlist applies to MCP keys as to the HTTP API.
			mcpHTTP := hiboumcp.NewHTTPServer(mcpSrv, queries, cfg.MCPPort, log, hiboumcp.WithUserAllowed(authMgr.UserAllowed))
			services++
			go func() {
				errCh <- runAuxServer(ctx, "MCP", mcpHTTP, cfg.MCPListenAddr(), cfg.ShutdownTimeout, log)
			}()
		}

		for i := 0; i < services; i++ {
			if err := <-errCh; err != nil {
				stop()
				return err
			}
		}

		return nil
	},
}

// metricsServer adapts http.Server to runAuxServer's Start/Shutdown shape.
type metricsServer struct{ *http.Server }

func (m *metricsServer) Start(addr string) error {
	m.Addr = addr
	return m.ListenAndServe()
}

// runAuxServer runs a secondary listener (MCP, metrics) until ctx ends.
func runAuxServer(ctx context.Context, name string, srv interface {
	Start(addr string) error
	Shutdown(ctx context.Context) error
}, addr string, shutdownTimeout time.Duration, log zerolog.Logger) error {
	errCh := make(chan error, 1)

	go func() {
		log.Info().Str("addr", addr).Msg(name + " server starting")
		if err := srv.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-errCh:
		return err
	}
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
}
