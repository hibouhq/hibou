// Package server provides the HTTP server that hosts the API and embedded SPA.
package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	"github.com/hibouhq/hibou/internal/api"
	_ "github.com/hibouhq/hibou/internal/apidoc"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/compliance"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/orgprovision"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/repoinventory"
	"github.com/hibouhq/hibou/internal/retention"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/toolcatalog"
	"github.com/hibouhq/hibou/internal/version"
	"github.com/hibouhq/hibou/internal/ws"
)

type Server struct {
	cfg               config.Config
	db                *sql.DB
	enforcer          *rbac.Enforcer
	authMgr           *auth.Manager
	forges            map[string]forge.Provider
	log               zerolog.Logger
	queries           *store.Queries
	bus               *events.Bus
	objStore          objstore.Store
	wsHub             *ws.Hub
	notifySvc         *notify.Service
	deltaSvc          *delta.Service
	repoConfigLoader  *repoconfig.Loader
	onboardingSvc     *repoconfig.OnboardingService
	inventorySvc      *repoinventory.Service
	orgProvisionSvc   *orgprovision.Service
	complianceSvc     *compliance.Service
	toolCatalogSvc    *toolcatalog.Service
	retentionWorker   *retention.Worker
	dispatcher        *notify.Dispatcher
	staleScanChecker  *notify.StaleScanChecker
	annotator         *forge.Annotator
	forgeIPAllowlists map[string]*forgeIPAllowlist
	forgeLimiters     map[string]*ipRateLimiter
	webhookHandlers   map[string][]forgeEventHandler
	lifecycleCtx      context.Context
	shutdownCancel    context.CancelFunc
	startedAt         time.Time
	router            chi.Router
	http              *http.Server
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
	lifecycleCtx, shutdownCancel := context.WithCancel(context.Background())
	configureRouter(r, log)

	s := &Server{
		cfg:             cfg,
		db:              db,
		enforcer:        enforcer,
		authMgr:         authMgr,
		forges:          forges,
		log:             log,
		lifecycleCtx:    lifecycleCtx,
		shutdownCancel:  shutdownCancel,
		queries:         store.NewQueries(db),
		bus:             events.New(log),
		startedAt:       time.Now(),
		router:          r,
		webhookHandlers: make(map[string][]forgeEventHandler),
		http: &http.Server{
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}
	initializeServerServices(s, cfg, log, forges)
	configureForgeProtection(s, cfg, log)

	s.routes(siteFS)
	return s
}

func configureRouter(r chi.Router, log zerolog.Logger) {
	r.Use(middleware.ClientIPFromXFFTrustedProxies(1))
	r.Use(middleware.RequestID)
	r.Use(requestLogger(log))
	r.Use(middleware.Recoverer)
}

func initializeServerServices(s *Server, cfg config.Config, log zerolog.Logger, forges map[string]forge.Provider) {
	s.wsHub = ws.NewHub(log)
	artifactStore, err := objstore.NewFilesystemStore(cfg.ArtifactPath)
	if err != nil {
		log.Error().Err(err).Str("path", cfg.ArtifactPath).Msg("failed to initialize artifact store")
	} else {
		s.objStore = artifactStore
	}
	s.notifySvc = notify.NewService(s.queries, s.wsHub, s.bus, log)
	deltaStore := delta.NewStoreAdapter(s.queries)
	s.deltaSvc = delta.NewService(deltaStore, log, deltaStore)
	s.repoConfigLoader = repoconfig.NewLoader(s.forges, log)
	s.onboardingSvc = repoconfig.NewOnboardingService(s.forges, log)
	s.inventorySvc = repoinventory.NewService(s.queries, s.forges, log)
	s.orgProvisionSvc = orgprovision.NewService(orgprovision.NewStoreAdapter(s.queries), s.enforcer, s.forges, cfg.AutoProvisionOrgs, log)
	s.complianceSvc = compliance.NewService(compliance.NewStoreAdapter(s.queries), log)
	s.toolCatalogSvc = toolcatalog.NewService(toolcatalog.NewStoreAdapter(s.queries))
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
	s.staleScanChecker = notify.NewStaleScanChecker(s.queries, s.bus, log)
	s.annotator = forge.NewAnnotator(forges, s.deltaSvc, s.bus, forge.NewAnnotatorStoreAdapter(s.queries), repoConfigGateLoader{loader: s.repoConfigLoader}, log)
	s.notifySvc.Subscribe()
	s.dispatcher.Subscribe()
	s.annotator.Subscribe()
	s.registerDefaultWebhookHandlers()
}

func configureForgeProtection(s *Server, cfg config.Config, log zerolog.Logger) {
	s.forgeIPAllowlists = make(map[string]*forgeIPAllowlist)
	s.forgeLimiters = make(map[string]*ipRateLimiter)
	for _, fc := range cfg.Forges {
		configureForgeAllowlist(s, fc, log)
		configureForgeRateLimiter(s, fc)
	}
}

func configureForgeAllowlist(s *Server, fc config.ForgeConfig, log zerolog.Logger) {
	if !fc.IPAllowlist && fc.AllowedCIDRs == "" {
		return
	}
	var source forgeIPSource
	if fc.Type == "github" {
		source = newGitHubIPSource(fc.URL)
	}
	cidrs := forgeDefaultCIDRs(fc, log)
	if source != nil || len(cidrs) > 0 {
		s.forgeIPAllowlists[fc.ID] = newForgeIPAllowlist(s.lifecycleCtx, log, source, cidrs)
	}
}

func configureForgeRateLimiter(s *Server, fc config.ForgeConfig) {
	if fc.RateLimitRPS > 0 {
		s.forgeLimiters[fc.ID] = newIPRateLimiter(s.lifecycleCtx, fc.RateLimitRPS, int(fc.RateLimitRPS)*5)
	}
}

// forgeDefaultCIDRs returns the static CIDR list for a forge. User-provided
// AllowedCIDRs always take precedence. For GitLab SaaS (no custom URL),
// built-in defaults are used when none are specified.
func forgeDefaultCIDRs(fc config.ForgeConfig, log zerolog.Logger) []string {
	if fc.AllowedCIDRs != "" {
		return strings.Split(fc.AllowedCIDRs, ",")
	}

	if fc.Type == "gitlab" {
		if fc.URL == "" {
			log.Info().Str("forge", fc.ID).Msg("using built-in GitLab SaaS IP ranges")
			return gitlabSaaSCIDRs
		}
		log.Warn().Str("forge", fc.ID).Msg("self-hosted GitLab with IP allowlist but no AllowedCIDRs configured")
	}

	return nil
}

func (s *Server) routes(siteFS fs.FS) {
	s.router.Handle("/metrics", promhttp.Handler())
	s.router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/ready", s.handleReady)
		r.Get("/metrics", s.handleMetrics)
		r.Get("/bin/version", s.handleBinVersion)
		r.Get("/bin/{os}/{arch}", s.handleBinDownload)
		r.Get("/schemas/hibou-config.schema.json", s.handleGetConfigSchema)
		r.Get("/ws", s.wsHub.HTTPHandler(s.authMgr, s.queries))
		r.Get("/docs/*", httpSwagger.Handler(
			httpSwagger.URL("/api/v1/docs/doc.json"),
		))
		r.Get("/auth/providers", auth.ProvidersHandler(s.authMgr))
		r.Get("/auth/login", auth.LoginHandler(s.authMgr))
		r.Get("/auth/callback", s.handleAuthCallback)
		r.Post("/auth/logout", auth.LogoutHandler(s.authMgr))
		r.Post("/auth/dev-login", auth.DevLoginHandler(s.authMgr))
		r.Route("/webhooks/{provider}", func(r chi.Router) {
			r.Use(s.webhookProtection)
			r.Post("/", s.handleWebhook)
		})

		r.Group(func(r chi.Router) {
			r.Use(auth.SessionAuth(s.authMgr, s.queries))
			r.Post("/auth/cli-token", s.handleCreateCLIToken)
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
				r.Get("/onboardable", s.handleListOnboardableOrgs)
				r.Post("/", s.handleCreateOrg)
				r.Get("/", s.handleListOrgs)
				r.Route("/{provider}/{slug}", func(r chi.Router) {
					r.Get("/", s.handleGetOrg)
					r.Put("/", s.handleUpdateOrg)
					r.Delete("/", s.handleDeleteOrg)
					r.Get("/dashboard", s.handleGetOrgDashboard)
					r.Get("/compliance/export", s.handleComplianceExport)
					r.Get("/compliance/iso27001", s.handleISO27001Export)
					r.Get("/compliance/soa", s.handleSoAExport)
					r.Get("/settings", s.handleGetOrgSettings)
					r.Put("/settings", s.handleUpdateOrgSettings)
					r.Get("/audit-logs", s.handleListAuditLogs)
					r.Get("/tool-catalog", s.handleGetToolCatalog)
					r.Get("/search", s.handleGlobalSearch)
					r.Route("/members", func(r chi.Router) {
						r.Get("/", s.handleListOrgMembers)
						r.Post("/", s.handleAddOrgMember)
						r.Put("/{userID}/role", s.handleUpdateOrgMemberRole)
						r.Delete("/{userID}", s.handleRemoveOrgMember)
					})
					r.Route("/integrations", func(r chi.Router) {
						r.Post("/", s.handleCreateIntegration)
						r.Get("/", s.handleListIntegrations)
						r.Route("/{integrationID}", func(r chi.Router) {
							r.Get("/", s.handleGetIntegration)
							r.Get("/health", s.handleGetIntegrationHealth)
							r.Post("/replay", s.handleReplayIntegration)
							r.Put("/", s.handleUpdateIntegration)
							r.Delete("/", s.handleDeleteIntegration)
						})
					})
					r.Route("/notification-rules", func(r chi.Router) {
						r.Post("/", s.handleCreateNotificationRule)
						r.Post("/dry-run", s.handleDryRunNotificationRule)
						r.Get("/", s.handleListNotificationRules)
						r.Route("/{ruleID}", func(r chi.Router) {
							r.Get("/", s.handleGetNotificationRule)
							r.Put("/", s.handleUpdateNotificationRule)
							r.Delete("/", s.handleDeleteNotificationRule)
						})
					})
					r.Route("/quality-gates", func(r chi.Router) {
						r.Post("/", s.handleCreateQualityGate)
						r.Get("/", s.handleListQualityGates)
						r.Route("/{gateID}", func(r chi.Router) {
							r.Get("/", s.handleGetQualityGate)
							r.Put("/", s.handleUpdateQualityGate)
							r.Delete("/", s.handleDeleteQualityGate)
						})
					})
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
							r.Route("/members", func(r chi.Router) {
								r.Get("/", s.handleListTeamMembers)
								r.Post("/", s.handleAddTeamMember)
								r.Put("/{userID}/role", s.handleUpdateTeamMemberRole)
								r.Delete("/{userID}", s.handleRemoveTeamMember)
							})
						})
					})
					r.Route("/repos", func(r chi.Router) {
						r.Post("/", s.handleEnrollRepo)
						r.Post("/sync", s.handleSyncRepos)
						r.Get("/", s.handleListRepos)
						r.Put("/{repoSlug}", s.handleUpdateRepo)
						r.Delete("/{repoSlug}", s.handleRemoveRepo)
						r.Get("/{repoSlug}", s.handleGetRepo)
						r.Post("/{repoSlug}/releases", s.handleCreateRelease)
						r.Get("/{repoSlug}/releases", s.handleListReleases)
						r.Get("/{repoSlug}/refs", s.handleListRefs)
						r.Get("/{repoSlug}/refs/enhanced", s.handleListRefsEnhanced)
						r.Get("/{repoSlug}/snapshots", s.handleListSnapshots)
						r.Get("/{repoSlug}/compare", s.handleCompareRefs)
						r.Get("/{repoSlug}/trends", s.handleGetTrends)
						r.Get("/{repoSlug}/pr/{number}", s.handleGetPRSummary)
						r.Get("/{repoSlug}/vulnerabilities", s.handleGetRefFindings)
						r.Get("/{repoSlug}/components", s.handleGetRefComponents)
						r.Get("/{repoSlug}/summary", s.handleGetRefSummary)
						r.Get("/{repoSlug}/coverage", s.handleGetCoverage)
						r.Get("/{repoSlug}/config", s.handleGetRepoConfig)
						r.Post("/{repoSlug}/onboard", s.handleOnboardRepo)
						r.Route("/{repoSlug}/vex", func(r chi.Router) {
							r.Post("/", s.handleCreateVEXStatement)
							r.Get("/", s.handleListVEXStatements)
							r.Get("/export", s.handleExportVEX)
							r.Get("/{statementID}", s.handleGetVEXStatement)
							r.Put("/{statementID}", s.handleUpdateVEXStatement)
							r.Delete("/{statementID}", s.handleDeleteVEXStatement)
						})
						r.Route("/{repoSlug}/delta", func(r chi.Router) {
							r.Get("/", s.handleGetDelta)
						})
					})
				})
			})
			r.Post("/upload", s.handleUploadAuto)
			r.Get("/uploads/{id}/status", s.handleGetUploadStatus)
		})
	})

	if siteFS != nil {
		s.router.Handle("/*", spaHandler(siteFS))
	} else {
		s.router.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Hibou</title></head><body style="font-family:system-ui;background:#0d1117;color:#c9d1d9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1>🦉 Hibou</h1><p>Frontend not built. Run <code style="background:#161b22;padding:2px 8px;border-radius:4px">make build-frontend</code> then restart,<br>or use the Vite dev server on <a href="http://localhost:3000" style="color:#58a6ff">port 3000</a>.</p></div></body></html>`)
		}))
	}
}

// webhookProtection dynamically applies per-forge IP allowlisting and rate
// limiting based on the {provider} URL parameter.
func (s *Server) webhookProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := chi.URLParam(r, "provider")
		handler := next

		if lim, ok := s.forgeLimiters[provider]; ok {
			handler = lim.Middleware(handler)
		}
		if al, ok := s.forgeIPAllowlists[provider]; ok {
			handler = al.Middleware(handler)
		}

		handler.ServeHTTP(w, r)
	})
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr())
	if err != nil {
		return err
	}

	if s.retentionWorker != nil {
		go s.runRetentionLoop(ctx)
	}
	if s.staleScanChecker != nil {
		go s.staleScanChecker.Start(ctx)
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
		return s.Shutdown(shutdownCtx)
	case err := <-errCh:
		if s.shutdownCancel != nil {
			s.shutdownCancel()
		}
		return err
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.shutdownCancel != nil {
		s.shutdownCancel()
	}
	return s.http.Shutdown(ctx)
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
