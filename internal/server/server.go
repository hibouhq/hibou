// Package server provides the HTTP server that hosts the API and embedded SPA.
package server

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/hibouhq/lehibou/internal/api"
	_ "github.com/hibouhq/lehibou/internal/apidoc"
	"github.com/hibouhq/lehibou/internal/auth"
	"github.com/hibouhq/lehibou/internal/config"
	"github.com/hibouhq/lehibou/internal/forge"
	"github.com/hibouhq/lehibou/internal/rbac"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/version"
)

type Server struct {
	cfg       config.Config
	db        *sql.DB
	enforcer  *rbac.Enforcer
	authMgr   *auth.Manager
	forges    map[string]forge.Provider
	log       zerolog.Logger
	queries   *store.Queries
	startedAt time.Time
	router    chi.Router
	http      *http.Server
}

type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type readyResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type metricsResponse struct {
	UptimeSeconds float64 `json:"uptime_seconds"`
	GoVersion     string  `json:"go_version"`
}

func New(cfg config.Config, log zerolog.Logger, db *sql.DB, enforcer *rbac.Enforcer, authMgr *auth.Manager, forges map[string]forge.Provider, siteFS fs.FS) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(requestLogger(log))
	r.Use(middleware.Recoverer)

	s := &Server{
		cfg:       cfg,
		db:        db,
		enforcer:  enforcer,
		authMgr:   authMgr,
		forges:    forges,
		log:       log,
		queries:   store.NewQueries(db),
		startedAt: time.Now(),
		router:    r,
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
		r.Get("/ready", s.handleReady)
		r.Get("/metrics", s.handleMetrics)
		r.Get("/docs/*", httpSwagger.Handler(
			httpSwagger.URL("/api/v1/docs/doc.json"),
		))
		r.Get("/auth/providers", auth.ProvidersHandler(s.authMgr))
		r.Get("/auth/login", auth.LoginHandler(s.authMgr))
		r.Get("/auth/callback", auth.CallbackHandler(s.authMgr))
		r.Post("/auth/logout", auth.LogoutHandler(s.authMgr))
		r.Post("/auth/dev-login", auth.DevLoginHandler(s.authMgr))
		r.Post("/webhooks/{provider}", s.handleWebhook)

		r.Group(func(r chi.Router) {
			r.Use(auth.SessionAuth(s.authMgr, s.queries))
			r.Get("/users/me", s.handleGetMe)
			r.Route("/users/me/api-keys", func(r chi.Router) {
				r.Post("/", s.handleCreateAPIKey)
				r.Get("/", s.handleListAPIKeys)
				r.Delete("/{keyID}", s.handleDeleteAPIKey)
			})
			r.Route("/orgs", func(r chi.Router) {
				r.Post("/", s.handleCreateOrg)
				r.Get("/", s.handleListOrgs)
				r.Route("/{slug}", func(r chi.Router) {
					r.Get("/", s.handleGetOrg)
					r.Put("/", s.handleUpdateOrg)
					r.Delete("/", s.handleDeleteOrg)
					r.Route("/teams", func(r chi.Router) {
						r.Post("/", s.handleCreateTeam)
						r.Get("/", s.handleListTeams)
						r.Route("/{teamSlug}", func(r chi.Router) {
							r.Get("/", s.handleGetTeam)
							r.Put("/", s.handleUpdateTeam)
							r.Delete("/", s.handleDeleteTeam)
						})
					})
					r.Route("/repos", func(r chi.Router) {
						r.Get("/", s.handleListRepos)
						r.Get("/{repoSlug}", s.handleGetRepo)
					})
				})
			})
			r.Post("/upload/sbom", s.handleUploadSBOM)
			r.Post("/upload/sarif", s.handleUploadSARIF)
			r.Post("/upload/findings", s.handleUploadFindings)
			r.Get("/uploads/{id}/status", s.handleGetUploadStatus)
		})
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

// @Summary      Health check
// @Description  Returns server health status
// @Tags         system
// @Produce      json
// @Success      200  {object}  api.Response{data=server.healthResponse}
// @Router       /health [get]
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	storeHealth := healthResponse{
		Status:  "ok",
		Version: version.Version,
	}

	api.JSON(w, http.StatusOK, storeHealth)
}

// @Summary      Readiness check
// @Description  Returns server readiness status based on database connectivity
// @Tags         system
// @Produce      json
// @Success      200  {object}  api.Response{data=server.readyResponse}
// @Failure      503  {object}  api.Response{data=server.readyResponse}
// @Router       /ready [get]
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.db == nil || s.db.PingContext(r.Context()) != nil {
		api.JSON(w, http.StatusServiceUnavailable, readyResponse{
			Status: "not ready",
			Reason: "database unavailable",
		})
		return
	}

	api.JSON(w, http.StatusOK, readyResponse{Status: "ready"})
}

// @Summary      Metrics
// @Description  Returns basic server metrics
// @Tags         system
// @Produce      json
// @Success      200  {object}  api.Response{data=server.metricsResponse}
// @Router       /metrics [get]
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	api.JSON(w, http.StatusOK, metricsResponse{
		UptimeSeconds: time.Since(s.startedAt).Seconds(),
		GoVersion:     runtime.Version(),
	})
}
