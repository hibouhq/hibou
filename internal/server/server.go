// Package server provides the HTTP server that hosts the API and embedded SPA.
package server

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/config"
	"github.com/hibouhq/lehibou/internal/version"
)

type Server struct {
	cfg    config.Config
	log    zerolog.Logger
	router chi.Router
	http   *http.Server
}

func New(cfg config.Config, log zerolog.Logger, siteFS fs.FS) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(requestLogger(log))
	r.Use(middleware.Recoverer)

	s := &Server{
		cfg:    cfg,
		log:    log,
		router: r,
		http: &http.Server{
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}

	s.routes(siteFS)
	return s
}

func (s *Server) routes(siteFS fs.FS) {
	s.router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
	})

	if siteFS != nil {
		s.router.Handle("/*", spaHandler(siteFS))
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr())
	if err != nil {
		return err
	}

	s.log.Info().
		Str("addr", ln.Addr().String()).
		Str("version", version.Version).
		Msg("server started")

	errCh := make(chan error, 1)
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.log.Info().Msg("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","version":"` + version.Version + `"}`))
}
