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
	"github.com/hibouhq/lehibou/internal/compliance"
	"github.com/hibouhq/lehibou/internal/config"
	"github.com/hibouhq/lehibou/internal/delta"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/forge"
	"github.com/hibouhq/lehibou/internal/notify"
	"github.com/hibouhq/lehibou/internal/objstore"
	"github.com/hibouhq/lehibou/internal/rbac"
	"github.com/hibouhq/lehibou/internal/repoconfig"
	"github.com/hibouhq/lehibou/internal/retention"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/version"
	"github.com/hibouhq/lehibou/internal/ws"
)

type Server struct {
	cfg              config.Config
	db               *sql.DB
	enforcer         *rbac.Enforcer
	authMgr          *auth.Manager
	forges           map[string]forge.Provider
	log              zerolog.Logger
	queries          *store.Queries
	bus              *events.Bus
	objStore         objstore.Store
	wsHub            *ws.Hub
	notifySvc        *notify.Service
	deltaSvc         *delta.Service
	repoConfigLoader *repoconfig.Loader
	onboardingSvc    *repoconfig.OnboardingService
	complianceSvc    *compliance.Service
	retentionWorker  *retention.Worker
	dispatcher       *notify.Dispatcher
	annotator        *forge.Annotator
	startedAt        time.Time
	router           chi.Router
	http             *http.Server
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

const retentionInterval = 24 * time.Hour

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
		bus:       events.New(log),
		startedAt: time.Now(),
		router:    r,
		http: &http.Server{
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}

	s.wsHub = ws.NewHub(log)
	artifactStore, err := objstore.NewFilesystemStore(cfg.ArtifactPath)
	if err != nil {
		log.Error().Err(err).Str("path", cfg.ArtifactPath).Msg("failed to initialize artifact store")
	} else {
		s.objStore = artifactStore
	}
	s.notifySvc = notify.NewService(s.queries, s.wsHub, s.bus, log)
	s.deltaSvc = delta.NewService(delta.NewStoreAdapter(s.queries), log)
	s.repoConfigLoader = repoconfig.NewLoader(s.forges, log)
	s.onboardingSvc = repoconfig.NewOnboardingService(s.forges, log)
	s.complianceSvc = compliance.NewService(compliance.NewStoreAdapter(s.queries), log)
	if s.objStore != nil {
		s.retentionWorker = retention.NewWorker(retention.NewStoreAdapter(s.queries), s.objStore, log, retention.DefaultPolicy())
	}
	s.dispatcher = notify.NewDispatcher(s.queries, s.bus, log,
		&notify.SlackSender{},
		&notify.TeamsSender{},
		&notify.DiscordSender{},
		&notify.WebhookSender{},
		&notify.EmailSender{},
	)
	s.annotator = forge.NewAnnotator(forges, s.deltaSvc, s.bus, forge.NewAnnotatorStoreAdapter(s.queries), repoConfigGateLoader{loader: s.repoConfigLoader}, log)
	s.notifySvc.Subscribe()
	s.dispatcher.Subscribe()
	s.annotator.Subscribe()

	s.routes(siteFS)
	return s
}

func (s *Server) routes(siteFS fs.FS) {
	s.router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/ready", s.handleReady)
		r.Get("/metrics", s.handleMetrics)
		r.Get("/schemas/hibou-config.schema.json", s.handleGetConfigSchema)
		r.Get("/ws", s.wsHub.HTTPHandler(s.authMgr, s.queries))
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
			r.Get("/notifications", s.notifySvc.HandleListNotifications)
			r.Get("/notifications/unread-count", s.notifySvc.HandleUnreadCount)
			r.Post("/notifications/{id}/read", s.notifySvc.HandleMarkRead)
			r.Post("/notifications/read-all", s.notifySvc.HandleMarkAllRead)
			r.Route("/users/me/api-keys", func(r chi.Router) {
				r.Post("/", s.handleCreateAPIKey)
				r.Get("/", s.handleListAPIKeys)
				r.Delete("/{keyID}", s.handleDeleteAPIKey)
			})
			r.Route("/orgs", func(r chi.Router) {
				r.Post("/", s.handleCreateOrg)
				r.Get("/", s.handleListOrgs)
				r.Route("/{provider}/{slug}", func(r chi.Router) {
					r.Get("/", s.handleGetOrg)
					r.Put("/", s.handleUpdateOrg)
					r.Delete("/", s.handleDeleteOrg)
					r.Get("/dashboard", s.handleGetOrgDashboard)
					r.Get("/compliance/export", s.handleComplianceExport)
					r.Get("/audit-logs", s.handleListAuditLogs)
					r.Get("/search", s.handleGlobalSearch)
					r.Route("/clients", func(r chi.Router) {
						r.Post("/", s.handleCreateClient)
						r.Get("/", s.handleListClients)
						r.Get("/label-keys", s.handleListClientLabelKeys)
						r.Route("/{clientSlug}", func(r chi.Router) {
							r.Get("/", s.handleGetClient)
							r.Put("/", s.handleUpdateClient)
							r.Delete("/", s.handleDeleteClient)
							r.Get("/deployments", s.handleListClientDeployments)
							r.Post("/deployments", s.handleCreateDeployment)
							r.Get("/impact", s.handleGetClientImpact)
						})
					})
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
						r.Post("/{repoSlug}/releases", s.handleCreateRelease)
						r.Get("/{repoSlug}/releases", s.handleListReleases)
						r.Get("/{repoSlug}/refs", s.handleListRefs)
						r.Get("/{repoSlug}/refs/enhanced", s.handleListRefsEnhanced)
						r.Get("/{repoSlug}/snapshots", s.handleListSnapshots)
						r.Get("/{repoSlug}/compare", s.handleCompareRefs)
						r.Get("/{repoSlug}/trends", s.handleGetTrends)
						r.Get("/{repoSlug}/pr/{number}", s.handleGetPRSummary)
						r.Get("/{repoSlug}/findings", s.handleGetRefFindings)
						r.Get("/{repoSlug}/components", s.handleGetRefComponents)
						r.Get("/{repoSlug}/summary", s.handleGetRefSummary)
						r.Get("/{repoSlug}/config", s.handleGetRepoConfig)
						r.Post("/{repoSlug}/onboard", s.handleOnboardRepo)
						r.Route("/{repoSlug}/delta", func(r chi.Router) {
							r.Get("/", s.handleGetDelta)
						})
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

	if s.retentionWorker != nil {
		go s.runRetentionLoop(ctx)
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

func (s *Server) runRetentionLoop(ctx context.Context) {
	if err := s.retentionWorker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Error().Err(err).Msg("retention pass failed")
	}

	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.retentionWorker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.log.Error().Err(err).Msg("retention pass failed")
			}
		}
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
