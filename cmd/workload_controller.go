package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/server"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/workload"
)

var workloadControllerCmd = &cobra.Command{
	Use: "workload-controller", Short: "Run the installation-managed Kubernetes workload controller", Hidden: true,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		log := newLogger(cfg)
		if err := cfg.ValidateStartup(log); err != nil {
			return err
		}
		managed, err := config.ManagedExecutionFromEnv()
		if err != nil || !managed.Enabled {
			return errors.New("kubernetes remediation must be explicitly configured and enabled")
		}
		client, err := workload.InClusterClient()
		if err != nil {
			return err
		}
		broker := workload.NewBroker()
		workloadConfig, err := workload.ConfigFromEnv()
		if err != nil {
			return err
		}
		runner, err := workload.NewRunner(workloadConfig, client, broker)
		if err != nil {
			return err
		}
		db, err := store.New(cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connect workload controller database: %w", err)
		}
		defer db.Close()
		forges, err := configuredForges(cfg, log)
		if err != nil {
			return err
		}
		srv, err := server.New(cfg, log, db, nil, nil, forges, nil)
		if err != nil {
			return err
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msg("shut down workload controller services")
			}
		}()
		certFile, keyFile := os.Getenv("HIBOU_WORKLOAD_TLS_CERT_FILE"), os.Getenv("HIBOU_WORKLOAD_TLS_KEY_FILE")
		if certFile == "" || keyFile == "" {
			return errors.New("workload broker requires TLS certificate and private key files")
		}
		brokerHTTP := &http.Server{
			Addr: ":8443", Handler: broker, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute,
			WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		group, runCtx := errgroup.WithContext(ctx)
		group.Go(func() error {
			err := brokerHTTP.ListenAndServeTLS(certFile, keyFile)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
		group.Go(func() error {
			return srv.RunManagedController(runCtx, runner, managed, 2*workloadConfig.Deadline+5*time.Minute)
		})
		group.Go(func() error {
			<-runCtx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return brokerHTTP.Shutdown(shutdownCtx)
		})
		return group.Wait()
	},
}
