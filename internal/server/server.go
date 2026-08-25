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
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/api"
	_ "github.com/hibouhq/hibou/internal/apidoc"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/cache"
	"github.com/hibouhq/hibou/internal/compliance"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/cvetriage"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/orgprovision"
	"github.com/hibouhq/hibou/internal/permissionsync"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/provider/osv"
	"github.com/hibouhq/hibou/internal/provider/trivy"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/repoinventory"
	"github.com/hibouhq/hibou/internal/retention"
	"github.com/hibouhq/hibou/internal/scanner"
	"github.com/hibouhq/hibou/internal/secretscan"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/toolcatalog"
	"github.com/hibouhq/hibou/internal/updatecheck"
	"github.com/hibouhq/hibou/internal/version"
	"github.com/hibouhq/hibou/internal/ws"
)

type Server struct {
	cfg                config.Config
	db                 *sql.DB
	enforcer           *rbac.Enforcer
	authMgr            *auth.Manager
	forges             map[string]forge.Provider
	log                zerolog.Logger
	queries            *store.Queries
	bus                *events.Bus
	objStore           objstore.Store
	wsHub              *ws.Hub
	wsFanout           ws.LiveDelivery
	wsListener         closeableListener
	notifySvc          *notify.Service
	deltaSvc           *delta.Service
	repoConfigLoader   *repoconfig.Loader
	onboardingSvc      *repoconfig.OnboardingService
	inventorySvc       *repoinventory.Service
	orgProvisionSvc    *orgprovision.Service
	permissionSyncSvc  *permissionsync.Service
	complianceSvc      *compliance.Service
	toolCatalogSvc     *toolcatalog.Service
	advisoryScanner    advisoryScanner
	advisoryIngester   *advisory.Ingester
	advisoryProviders  []string
	secretScanner      *secretscan.Scanner
	secretScanSlots    chan struct{}
	secretCheckSlots   chan struct{}
	retentionWorker    *retention.Worker
	dispatcher         *notify.Dispatcher
	staleScanChecker   backgroundStarter
	tokenExpiryChecker backgroundStarter
	updateChecker      *updatecheck.Checker
	gatePublisher      *forge.GatePublisher
	instanceAdmins     instanceAdminState
	forgeIPAllowlists  map[string]*forgeIPAllowlist
	forgeLimiters      map[string]*ipRateLimiter
	webhookHandlers    map[string][]forgeEventHandler
	artifactWorkerID   string
	enabledLoops       []string
	lifecycleCtx       context.Context
	shutdownCancel     context.CancelFunc
	startedAt          time.Time
	router             chi.Router
	http               *http.Server
	draining           atomic.Bool
	artifactStateMu    sync.Mutex
	artifactIdleCh     chan struct{}
	artifactInFlight   map[uuid.UUID]struct{}
	activeArtifacts    int
	advisoryScanActive atomic.Bool
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
	// SecretScanQueueDepth counts pending + in-flight jobs — the worker
	// autoscaling signal. Omitted when secret scanning is disabled.
	SecretScanQueueDepth *int64 `json:"secret_scan_queue_depth,omitempty"`
}

type backgroundStarter interface {
	Start(context.Context)
}

type advisoryScanner interface {
	RunScan(ctx context.Context, snapshotID uuid.UUID, providerNames []string, triggeredBy string) (uuid.UUID, error)
	TriggerRescan(ctx context.Context, snapshotID uuid.UUID, providerNames []string, actor audit.Entry) (uuid.UUID, error)
}

type closeableListener interface {
	Close() error
}

var newBridgeListener = func(databaseURL, channel string, handler func(ws.Envelope), log zerolog.Logger) (closeableListener, error) {
	return ws.NewPostgresListener(databaseURL, channel, handler, log)
}

const retentionInterval = 24 * time.Hour
const stalePendingInterval = 1 * time.Minute

func New(cfg config.Config, log zerolog.Logger, db *sql.DB, enforcer *rbac.Enforcer, authMgr *auth.Manager, forges map[string]forge.Provider, siteFS fs.FS) (*Server, error) {
	r := chi.NewRouter()
	lifecycleCtx, shutdownCancel := context.WithCancel(context.Background())
	configureRouter(r, log)

	s := &Server{
		cfg:              cfg,
		db:               db,
		enforcer:         enforcer,
		authMgr:          authMgr,
		forges:           forges,
		log:              log,
		lifecycleCtx:     lifecycleCtx,
		shutdownCancel:   shutdownCancel,
		queries:          store.NewQueries(db),
		bus:              events.New(log),
		startedAt:        time.Now(),
		router:           r,
		artifactWorkerID: newArtifactWorkerID(),
		webhookHandlers:  make(map[string][]forgeEventHandler),
		updateChecker:    updatecheck.New(version.Version, log),
		http: &http.Server{
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}
	r.Use(s.shutdownMiddleware)
	if err := initializeServerServices(s, cfg, log, forges); err != nil {
		shutdownCancel()
		return nil, err
	}
	configureForgeProtection(s, cfg, log)

	s.routes(siteFS)
	return s, nil
}

func configureRouter(r chi.Router, log zerolog.Logger) {
	r.Use(middleware.ClientIPFromXFFTrustedProxies(1))
	r.Use(middleware.RequestID)
	r.Use(requestLogger(log))
	r.Use(middleware.Recoverer)
}

func initializeServerServices(s *Server, cfg config.Config, log zerolog.Logger, forges map[string]forge.Provider) error {
	success := false
	defer func() {
		if success || s.wsListener == nil {
			return
		}
		if err := s.wsListener.Close(); err != nil {
			log.Warn().Err(err).Msg("close postgres websocket listener after startup failure")
		}
		s.wsListener = nil
	}()

	initializeWebsocketFanout(s, cfg, log)
	backend := normalizeArtifactBackend(cfg.ArtifactBackend)
	artifactStore, err := newArtifactStore(cfg, backend)
	if err != nil {
		return fmt.Errorf("initialize artifact backend %q: %w", backend, err)
	}
	s.objStore = artifactStore
	s.notifySvc = notify.NewService(s.queries, s.wsFanout, s.bus, log)
	deltaStore := delta.NewStoreAdapter(s.queries)
	s.deltaSvc = delta.NewService(deltaStore, log, deltaStore)
	s.repoConfigLoader = repoconfig.NewLoader(s.forges, log)
	s.onboardingSvc = repoconfig.NewOnboardingService(s.forges, log)
	s.inventorySvc = repoinventory.NewService(s.queries, s.forges, log)
	s.orgProvisionSvc = orgprovision.NewService(orgprovision.NewStoreAdapter(s.queries), s.enforcer, s.forges, cfg.AutoProvisionOrgs, log)
	s.permissionSyncSvc = permissionsync.NewService(permissionsync.NewStoreAdapter(s.queries), s.enforcer, s.forges, log).
		// A suspended grant is inert: somebody who could triage yesterday
		// cannot today, and without a notification the first symptom is a
		// queue quietly going unworked.
		WithPublisher(s.bus)
	s.complianceSvc = compliance.NewService(compliance.NewStoreAdapter(s.queries), log)
	s.toolCatalogSvc = toolcatalog.NewService(toolcatalog.NewStoreAdapter(s.queries))
	providers := buildAdvisoryProviders(cfg, log)
	advisoryCache := cache.New(s.queries, cache.Config{DefaultTTL: cfg.CacheTTL}, log)
	advisoryIngester := advisory.NewIngester(s.queries, log)
	// Triage authors advisory data through the same ingester every provider
	// uses, which is what makes an authored mapping indistinguishable
	// downstream from one that arrived from OSV.
	s.advisoryIngester = advisoryIngester
	s.advisoryScanner = scanner.New(s.queries, advisoryCache, advisoryIngester, s.bus, providers, log)
	s.advisoryProviders = configuredAdvisoryProviderNames(cfg.AdvisoryScan.Providers, providers)
	if len(s.advisoryProviders) == 0 {
		log.Info().Strs("configured_providers", append([]string(nil), cfg.AdvisoryScan.Providers...)).Msg("advisory scanning disabled: no supported providers are configured")
	}
	if s.authMgr != nil && s.permissionSyncSvc != nil {
		s.authMgr.AddLoginHook(func(ctx context.Context, user *store.User, providerID string, token *oauth2.Token) {
			if err := s.permissionSyncSvc.SyncUser(ctx, user, providerID, token); err != nil {
				s.log.Error().Err(err).Str("user_id", user.ID.String()).Str("provider", providerID).Msg("failed to sync forge permissions after login")
			}
		})
	}
	if cfg.SecretScan.Enabled {
		secretProviders := buildSecretScanProviders(cfg, log)
		if len(secretProviders) > 0 {
			s.secretScanner = secretscan.NewScanner(secretProviders, s.queries, s.bus, log, cfg.SecretScan.TempDir)
			s.secretScanSlots = make(chan struct{}, cfg.SecretScan.MaxConcurrency)
			// The synchronous push-check path blocks a caller's push, so it gets
			// its own small limiter rather than competing for worker slots.
			s.secretCheckSlots = make(chan struct{}, 2)
		} else {
			log.Info().Strs("configured_providers", append([]string(nil), cfg.SecretScan.Providers...)).Msg("secret scanning enabled but no providers are usable on this pod")
		}
	}
	s.retentionWorker = retention.NewWorker(retention.NewStoreAdapter(s.queries), s.objStore, s.queries, s.bus, log, cfg.RetentionPolicy, cfg.UploadWindow)
	s.dispatcher = notify.NewDispatcher(s.queries, s.bus, cfg.BaseURL, log,
		&notify.SlackSender{},
		&notify.TeamsSender{},
		&notify.DiscordSender{},
		&notify.WebhookSender{},
		&notify.EmailSender{},
	)
	s.staleScanChecker = notify.NewStaleScanChecker(s.queries, s.bus, log)
	s.tokenExpiryChecker = notify.NewTokenExpiryChecker(s.queries, s.bus, log)
	s.gatePublisher = forge.NewGatePublisher(forges, s.deltaSvc, s.bus, forge.NewGatePublisherStoreAdapter(s.queries), repoConfigGateLoader{loader: s.repoConfigLoader}, wsGateNotifier{live: s.wsFanout}, cfg.BaseURL, log)
	s.notifySvc.Subscribe()
	s.dispatcher.Subscribe()
	s.gatePublisher.Subscribe()
	s.registerDefaultWebhookHandlers()
	success = true
	return nil
}

func buildAdvisoryProviders(cfg config.Config, log zerolog.Logger) map[string]provider.AdvisoryProvider {
	providers := map[string]provider.AdvisoryProvider{}
	for _, name := range cfg.AdvisoryScan.Providers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "osv":
			providers["osv"] = osv.New(cfg.OSVURL, log)
		case "trivy":
			providers["trivy"] = trivy.New(cfg.TriviURL, log)
		}
	}
	return providers
}

func configuredAdvisoryProviderNames(configured []string, built map[string]provider.AdvisoryProvider) []string {
	providerNames := make([]string, 0, len(built))
	seen := make(map[string]struct{}, len(built))
	for _, name := range configured {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if normalized == "" {
			continue
		}
		if _, ok := built[normalized]; !ok {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		providerNames = append(providerNames, normalized)
		seen[normalized] = struct{}{}
	}
	return providerNames
}

func initializeWebsocketFanout(s *Server, cfg config.Config, log zerolog.Logger) {
	s.wsHub = ws.NewHub(log)
	dispatcher := ws.NewDispatcher(s.wsHub, log)
	publisher, listener, bridgeActive := configureWebsocketBridge(s.db, cfg.DatabaseURL, dispatcher, log)
	s.wsListener = listener
	s.wsFanout = ws.NewFanout(publisher, dispatcher, bridgeActive, log)
}

func configureWebsocketBridge(db *sql.DB, databaseURL string, dispatcher *ws.Dispatcher, log zerolog.Logger) (ws.Publisher, closeableListener, bool) {
	if databaseURL == "" || db == nil {
		return nil, nil, false
	}

	listener, err := newBridgeListener(databaseURL, ws.DefaultChannel, dispatcher.Dispatch, log)
	if err != nil {
		log.Warn().Err(err).Msg("postgres websocket listener failed to start; using local-only live delivery on this replica")
		return nil, nil, false
	}

	return ws.NewPostgresPublisher(db, ws.DefaultChannel), listener, true
}

func normalizeArtifactBackend(backend string) string {
	trimmed := strings.TrimSpace(strings.ToLower(backend))
	if trimmed == "" {
		return "filesystem"
	}
	return trimmed
}

func newArtifactStore(cfg config.Config, backend string) (objstore.Store, error) {
	switch backend {
	case "filesystem":
		return objstore.NewFilesystemStore(cfg.ArtifactPath)
	case "s3":
		return objstore.NewS3Store(objstore.S3Config{
			Endpoint:        cfg.ArtifactS3.Endpoint,
			Region:          cfg.ArtifactS3.Region,
			Bucket:          cfg.ArtifactS3.Bucket,
			AccessKeyID:     cfg.ArtifactS3.AccessKeyID,
			SecretAccessKey: cfg.ArtifactS3.SecretAccessKey,
			UsePathStyle:    cfg.ArtifactS3.UsePathStyle,
			UseSSL:          cfg.ArtifactS3.UseSSL,
		})
	default:
		return nil, fmt.Errorf("unknown artifact backend %q", backend)
	}
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
		r.Get("/version", s.handleVersion)
		r.Get("/schemas/hibou-config.schema.json", s.handleGetConfigSchema)
		r.Get("/ws", s.wsHub.HTTPHandler(s.authMgr, s.queries))
		r.Get("/docs/*", httpSwagger.Handler(
			httpSwagger.URL("/api/v1/docs/doc.json"),
		))
		// Public: the login page shows announcement banners too.
		r.Get("/instance/banners", s.handleListActiveBanners)
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
			r.Use(s.tokenScopeGuard)
			r.Get("/users/me", s.handleGetMe)
			r.Get("/instance/settings/banners", s.handleGetBannerSettings)
			r.Put("/instance/settings/banners", s.handleUpdateBannerSettings)
			r.Get("/instance/settings/admins", s.handleListInstanceAdmins)
			r.Get("/instance/jobs/overview", s.handleInstanceJobsOverview)
			r.Get("/instance/jobs/timeline", s.handleInstanceJobsTimeline)
			r.Get("/instance/jobs/stats", s.handleInstanceJobsStats)
			r.Get("/instance/audit-logs", s.handleListInstanceAuditLogs)
			// ADR-028. `advisories` not `cves`: the namespace has to hold
			// `HSA-*` once an advisory exists that no CVE covers (§10).
			r.Route("/instance/advisories", func(r chi.Router) {
				// Filtered by product only. An unfiltered list is refused:
				// §13 keeps the mirror as infrastructure, not a browser.
				r.Get("/", s.handleListAdvisories)
				r.Get("/events", s.handleAdvisoryEvents)
				// Instance-scoped: "Apache Tomcat means these artifacts" is a
				// fact about the world, not about one organization.
				r.Route("/watches", func(r chi.Router) {
					r.Get("/", s.handleListWatches)
					r.Post("/", s.handleCreateWatch)
					r.Get("/candidates", s.handleListWatchCandidates)
					r.Delete("/{watchID}", s.handleDeleteWatch)
				})
				r.Get("/{advisoryID}/events", s.handleAdvisoryTimeline)
			})
			// The cross-org answer to "what can this person do everywhere",
			// and the only home for roles no forge has an opinion about.
			r.Get("/instance/members", s.handleListInstanceMembers)
			r.Post("/instance/members/grants", s.handleGrantLocalRole)
			r.Post("/instance/members/revocations", s.handleRevokeLocalRole)
			r.Get("/notifications", s.notifySvc.HandleListNotifications)
			r.Get("/notifications/unread-count", s.notifySvc.HandleUnreadCount)
			r.Post("/notifications/{id}/read", s.notifySvc.HandleMarkRead)
			r.Post("/notifications/read-all", s.notifySvc.HandleMarkAllRead)
			r.Route("/users/me/api-keys", func(r chi.Router) {
				r.Post("/", s.handleCreateAPIKey)
				r.Get("/", s.handleListAPIKeys)
				r.Patch("/{keyID}", s.handleUpdateAPIKey)
				r.Delete("/{keyID}", s.handleDeleteAPIKey)
				r.Post("/{keyID}/rotate", s.handleRotateAPIKey)
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
					r.Get("/vulnerabilities", s.handleListOrgVulnerabilities)
					r.Get("/components", s.handleListOrgComponents)
					r.Post("/components/scan", s.handleTriggerOrgComponentScan)
					r.Get("/compliance/export", s.handleComplianceExport)
					r.Get("/compliance/iso27001", s.handleISO27001Export)
					r.Get("/compliance/soa", s.handleSoAExport)
					r.Get("/settings", s.handleGetOrgSettings)
					r.Put("/settings", s.handleUpdateOrgSettings)
					r.Get("/audit-logs", s.handleListAuditLogs)
					r.Route("/api-keys", func(r chi.Router) {
						r.Get("/", s.handleListOrgAPIKeys)
						r.Get("/exposure", s.handleListOrgTokenExposure)
						r.Post("/", s.handleCreateOrgAPIKey)
						r.Patch("/{keyID}", s.handleUpdateOrgAPIKey)
						r.Delete("/{keyID}", s.handleDeleteOrgAPIKey)
						r.Post("/{keyID}/rotate", s.handleRotateOrgAPIKey)
						r.Post("/{keyID}/approve", s.handleApproveOrgAPIKey)
						r.Post("/{keyID}/reject", s.handleRejectOrgAPIKey)
					})
					r.Get("/tool-catalog", s.handleGetToolCatalog)
					r.Get("/search", s.handleGlobalSearch)
					r.Route("/members", func(r chi.Router) {
						r.Get("/", s.handleListOrgMembers)
						r.Post("/", s.handleAddOrgMember)
						r.Put("/{userID}/role", s.handleUpdateOrgMemberRole)
						r.Delete("/{userID}", s.handleRemoveOrgMember)
					})
					// Watched software (ADR-028): products tracked by the name
					// their vendor publishes advisories under, because no
					// upstream record maps them to package coordinates.
					// Triage: the queue where a person supplies the package
					// identity no upstream record carries.
					r.Route("/triage", func(r chi.Router) {
						r.Get("/", s.handleListTriageQueue)
						r.Get("/{itemID}", s.handleGetTriageItem)
						r.Post("/{itemID}/decision", s.handleDecideTriageItem)
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
						r.Get("/{repoSlug}/releases", s.handleListReleases)
						r.Post("/{repoSlug}/releases/{releaseID}/divergence", s.handleResolveReleaseDivergence)
						r.Post("/{repoSlug}/releases/{releaseID}/clients", s.handleAddReleaseClient)
						r.Delete("/{repoSlug}/releases/{releaseID}/clients/{deploymentID}", s.handleRemoveReleaseClient)
						r.Get("/{repoSlug}/refs", s.handleListRefs)
						r.Get("/{repoSlug}/refs/enhanced", s.handleListRefsEnhanced)
						r.Get("/{repoSlug}/snapshots", s.handleListSnapshots)
						r.Get("/{repoSlug}/snapshots/{snapshotID}/files", s.handleListSnapshotFiles)
						r.Get("/{repoSlug}/snapshots/{snapshotID}/files.zip", s.handleDownloadSnapshotArchive)
						r.Get("/{repoSlug}/snapshots/{snapshotID}/files/{artifactID}", s.handleDownloadSnapshotFile)
						r.Get("/{repoSlug}/snapshots/{snapshotID}/coverage-source", s.handleGetCoverageSource)
						r.Post("/{repoSlug}/sbom/compare", s.handleCompareSBOMs)
						r.Get("/{repoSlug}/compare", s.handleCompareRefs)
						r.Get("/{repoSlug}/trends", s.handleGetTrends)
						r.Get("/{repoSlug}/findings", s.handleGetRefFindings)
						r.Post("/{repoSlug}/findings", s.handleCreateFinding)
						r.Get("/{repoSlug}/findings/facets", s.handleGetRefFindingFacets)
						r.Get("/{repoSlug}/vulnerabilities", s.handleGetRefFindings)
						r.Get("/{repoSlug}/vulnerabilities/facets", s.handleGetRefFindingFacets)
						r.Get("/{repoSlug}/vulnerabilities/rules", s.handleGetRefRules)
						r.Get("/{repoSlug}/vulnerabilities/fingerprints", s.handleGetRefFindingFingerprints)
						r.Get("/{repoSlug}/findings/{fingerprint}", s.handleGetFindingDetail)
						r.Get("/{repoSlug}/findings/{fingerprint}/history", s.handleGetFindingHistory)
						r.Post("/{repoSlug}/reachability", s.handleSubmitReachability)
						r.Put("/{repoSlug}/vulnerabilities/acceptance", s.handleBatchFindingAcceptance)
						r.Put("/{repoSlug}/vulnerabilities/{vulnID}/acceptance", s.handleSetFindingAcceptance)
						r.Put("/{repoSlug}/vulnerabilities/{vulnID}/dispute", s.handleSetFindingDispute)
						r.Delete("/{repoSlug}/vulnerabilities/{vulnID}/dispute", s.handleDeleteFindingDispute)
						r.Post("/{repoSlug}/vulnerabilities/{vulnID}/revocation", s.handleAttestSecretRevocation)
						r.Get("/{repoSlug}/finding-acceptances", s.handleListFindingAcceptances)
						r.Get("/{repoSlug}/components", s.handleGetRefComponents)
						r.Post("/{repoSlug}/components/scan", s.handleTriggerComponentScan)
						r.Post("/{repoSlug}/secrets/scan", s.handleTriggerSecretScan)
						r.Get("/{repoSlug}/secrets/jobs", s.handleListSecretScanJobs)
						r.Get("/{repoSlug}/components/graph", s.handleGetRefComponentGraph)
						r.Get("/{repoSlug}/summary", s.handleGetRefSummary)
						r.Get("/{repoSlug}/coverage", s.handleGetCoverage)
						r.Get("/{repoSlug}/tests", s.handleGetTests)
						r.Get("/{repoSlug}/config", s.handleGetRepoConfig)
						r.Get("/{repoSlug}/onboard", s.handleGetOnboardingStatus)
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
						r.Get("/{repoSlug}/pulls/{pr}/gate", s.handleGetPRGate)
					})
				})
			})
			r.Post("/secret-scan/check", s.handleSecretScanCheck)
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

// startBackgroundLoops launches the enabled background workers as goroutines
// bound to runtimeCtx.
func (s *Server) startBackgroundLoops(runtimeCtx context.Context) {
	loops := make([]string, 0, 10)
	if s.retentionWorker != nil && s.cfg.Background.RetentionEnabled {
		loops = append(loops, "retention")
		go s.runRetentionLoop(runtimeCtx)
	}
	if s.cfg.Background.StalePendingEnabled {
		loops = append(loops, "stale_pending")
		go s.runStalePendingLoop(runtimeCtx)
	}
	if s.objStore != nil && s.cfg.Background.ArtifactProcessingEnabled {
		loops = append(loops, "artifact_processing")
		go s.runArtifactProcessingLoop(runtimeCtx)
	}
	if s.advisoryScanner != nil && len(s.advisoryProviders) > 0 && s.cfg.AdvisoryScan.Interval > 0 {
		loops = append(loops, "advisory_scan")
		go s.runAdvisoryScanLoop(runtimeCtx)
	}
	if s.staleScanChecker != nil && s.cfg.Background.StaleScanEnabled {
		loops = append(loops, "stale_scan")
		go s.staleScanChecker.Start(runtimeCtx)
	}
	// The CVE feed sweep (ADR-028). Always on: a scanner that silently watches
	// nothing because a path was left unset is worse than a 10 MB clone.
	if s.db != nil && s.queries != nil {
		loops = append(loops, "cve_feed")
		sweeper := &cvetriage.Sweeper{
			Source: &cvefeed.GitSource{Dir: cveFeedDir(), Remote: s.cfg.CVEFeed.Remote},
			Store: &cveSweepStore{
				queries:  s.queries,
				db:       s.db,
				ingester: s.advisoryIngester,
				// Stable so auto-applied advisories are attributable to the
				// mechanism rather than to an arbitrary person.
				autoApplyActor: autoApplyActorID,
			},
			Log: s.log,
		}
		go s.runCVEFeedLoop(runtimeCtx, sweeper, s.cfg.CVEFeed.Interval)
	}
	if s.tokenExpiryChecker != nil && s.cfg.Background.StaleScanEnabled {
		loops = append(loops, "token_expiry")
		go s.tokenExpiryChecker.Start(runtimeCtx)
	}
	if s.secretScanner != nil && s.cfg.Background.SecretScanEnabled {
		loops = append(loops, "secret_scan")
		go s.runSecretScanLoop(runtimeCtx)
	}
	if s.gatePublisher != nil {
		loops = append(loops, "gate_reconcile")
		go s.gatePublisher.StartReconcileLoop(runtimeCtx, 5*time.Minute)
	}
	if s.updateChecker != nil {
		loops = append(loops, "update_check")
		go s.updateChecker.Start(runtimeCtx)
	}
	if s.cfg.InstanceAdminsFile != "" || len(s.cfg.InstanceAdmins) > 0 {
		loops = append(loops, "instance_admin_watch")
		go s.runInstanceAdminWatchLoop(runtimeCtx)
	}
	// Set before the heartbeat goroutine starts so it never races the append.
	s.enabledLoops = loops
	if s.queries != nil {
		go s.runWorkerHeartbeatLoop(runtimeCtx)
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr())
	if err != nil {
		return err
	}

	runtimeCtx := s.lifecycleCtx
	if runtimeCtx == nil {
		runtimeCtx = context.Background()
	}

	s.startBackgroundLoops(runtimeCtx)

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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
		defer cancel()
		return s.Shutdown(shutdownCtx)
	case err := <-errCh:
		if s.shutdownCancel != nil {
			s.shutdownCancel()
		}
		return err
	}
}

func newArtifactWorkerID() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), uuid.NewString())
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.beginDrain()

	httpErrCh := make(chan error, 1)
	go func() {
		httpErrCh <- s.http.Shutdown(ctx)
	}()

	artifactErr := s.waitForActiveArtifacts(ctx)
	httpErr := <-httpErrCh

	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), s.claimReleaseTimeout())
	defer releaseCancel()
	releaseErr := errors.Join(s.releaseArtifactClaims(releaseCtx), s.releaseSecretScanClaims(releaseCtx))
	if s.queries != nil {
		if err := s.queries.MarkWorkerStopped(releaseCtx, s.artifactWorkerID); err != nil {
			s.log.Warn().Err(err).Msg("marking worker stopped failed")
		}
	}
	wsErr := s.wsHubWaitForDrain(ctx)
	if errors.Is(wsErr, context.DeadlineExceeded) || errors.Is(wsErr, context.Canceled) {
		s.closeWebsockets()
		wsErr = nil
	} else {
		s.closeWebsockets()
	}

	listenerErr := s.closeWebsocketListener()
	if s.shutdownCancel != nil {
		s.shutdownCancel()
	}

	return errors.Join(httpErr, artifactErr, releaseErr, wsErr, listenerErr)
}

func (s *Server) shutdownTimeout() time.Duration {
	if s.cfg.ShutdownTimeout > 0 {
		return s.cfg.ShutdownTimeout
	}
	return 20 * time.Second
}

func (s *Server) claimReleaseTimeout() time.Duration {
	timeout := s.shutdownTimeout()
	if timeout > 5*time.Second {
		return 5 * time.Second
	}
	if timeout <= 0 {
		return 5 * time.Second
	}
	return timeout
}

func (s *Server) beginDrain() {
	first := false
	s.artifactStateMu.Lock()
	if !s.draining.Load() {
		s.draining.Store(true)
		first = true
	}
	s.artifactStateMu.Unlock()
	if first {
		s.log.Info().Dur("timeout", s.shutdownTimeout()).Msg("server entering drain mode")
	}
	if s.wsHub != nil {
		s.wsHub.BeginDrain()
	}
}

func (s *Server) isDraining() bool {
	return s.draining.Load()
}

func (s *Server) waitForActiveArtifacts(ctx context.Context) error {
	s.artifactStateMu.Lock()
	if s.activeArtifacts == 0 {
		s.artifactStateMu.Unlock()
		return nil
	}
	idleCh := s.artifactIdleCh
	s.artifactStateMu.Unlock()

	select {
	case <-idleCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) releaseArtifactClaims(ctx context.Context) error {
	if s.queries == nil || strings.TrimSpace(s.artifactWorkerID) == "" {
		return nil
	}
	inFlight := s.inFlightArtifactSnapshotIDs()
	if len(inFlight) > 0 {
		s.log.Warn().Int("in_flight_claims", len(inFlight)).Str("worker_id", s.artifactWorkerID).Msg("leaving in-flight artifact claims for lease recovery during shutdown")
	}
	count, err := s.releaseArtifactClaimsExcluding(ctx, inFlight)
	if err != nil {
		return err
	}
	if count > 0 {
		s.log.Info().Int64("released_claims", count).Str("worker_id", s.artifactWorkerID).Msg("released artifact processing claims during shutdown")
	}
	return nil
}

func (s *Server) releaseArtifactClaimsExcluding(ctx context.Context, excluded []uuid.UUID) (int64, error) {
	if len(excluded) == 0 {
		return s.queries.ReleaseArtifactProcessingClaims(ctx, s.artifactWorkerID)
	}

	excludedIDs := make([]string, 0, len(excluded))
	for _, snapshotID := range excluded {
		excludedIDs = append(excludedIDs, snapshotID.String())
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_claimed_by = NULL,
			artifact_processing_claim_expires_at = NULL
		WHERE artifact_processing_claimed_by = $1
			AND artifact_processing_finished_at IS NULL
			AND (status = 'processing' OR status = 'complete' OR status = 'failed')
			AND NOT (id = ANY($2::uuid[]))
	`, s.artifactWorkerID, pq.Array(excludedIDs))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Server) tryStartArtifactProcessing(snapshotID uuid.UUID) bool {
	s.artifactStateMu.Lock()
	defer s.artifactStateMu.Unlock()

	if s.draining.Load() {
		return false
	}
	if s.artifactInFlight == nil {
		s.artifactInFlight = make(map[uuid.UUID]struct{})
	}
	if s.activeArtifacts == 0 {
		s.artifactIdleCh = make(chan struct{})
	}
	s.artifactInFlight[snapshotID] = struct{}{}
	s.activeArtifacts++
	return true
}

func (s *Server) finishArtifactProcessing(snapshotID uuid.UUID) {
	s.artifactStateMu.Lock()
	defer s.artifactStateMu.Unlock()

	if _, ok := s.artifactInFlight[snapshotID]; !ok {
		return
	}
	delete(s.artifactInFlight, snapshotID)
	if s.activeArtifacts > 0 {
		s.activeArtifacts--
	}
	if s.activeArtifacts == 0 {
		closeArtifactIdleSignal(s.artifactIdleCh)
	}
}

func (s *Server) inFlightArtifactSnapshotIDs() []uuid.UUID {
	s.artifactStateMu.Lock()
	defer s.artifactStateMu.Unlock()

	if len(s.artifactInFlight) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(s.artifactInFlight))
	for snapshotID := range s.artifactInFlight {
		ids = append(ids, snapshotID)
	}
	return ids
}

func (s *Server) wsHubWaitForDrain(ctx context.Context) error {
	if s.wsHub == nil {
		return nil
	}
	return s.wsHub.WaitForZero(ctx)
}

func (s *Server) closeWebsockets() {
	if s.wsHub == nil {
		return
	}
	s.wsHub.CloseAll(websocket.StatusGoingAway, "server shutting down")
}

func (s *Server) closeWebsocketListener() error {
	if s.wsListener == nil {
		return nil
	}
	err := s.wsListener.Close()
	if err != nil {
		s.log.Warn().Err(err).Msg("close postgres websocket listener")
		s.wsListener = nil
		return nil
	}
	s.wsListener = nil
	return err
}

func closeArtifactIdleSignal(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
		return
	default:
		close(ch)
	}
}

func (s *Server) runRetentionLoop(ctx context.Context) {
	s.runRetentionPass(ctx)

	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runRetentionPass(ctx)
		}
	}
}

func (s *Server) runRetentionPass(ctx context.Context) {
	if s.retentionWorker == nil {
		return
	}
	// Singleton across replicas: the sweep is idempotent, but N replicas each
	// walking every repo is N× the work and N× the object-store delete traffic
	// for one identical outcome.
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockRetentionPass, func(runCtx context.Context) error {
		if s.queries != nil {
			if auditErr := s.queries.MaintainAuditLogPartitions(runCtx, time.Now(), s.cfg.AuditRetentionMonths); auditErr != nil {
				s.log.Warn().Err(auditErr).Msg("audit log partition maintenance")
			}
		}
		return s.retentionWorker.Run(runCtx)
	})
	// Shutdown cancellation is not a failure; keep the original filtering.
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Error().Err(err).Msg("retention pass failed")
		return
	}
	if !ran {
		s.log.Debug().Msg("another replica is running the retention pass; skipping this tick")
	}
}

func (s *Server) triggerRetentionPass() {
	if s.retentionWorker == nil {
		return
	}
	ctx := s.lifecycleCtx
	if ctx == nil {
		ctx = context.Background()
	}
	go s.runRetentionPass(ctx)
}

func (s *Server) runStalePendingLoop(ctx context.Context) {
	if s.retentionWorker == nil {
		return
	}

	if err := s.retentionWorker.SweepStalePending(ctx); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Error().Err(err).Msg("stale pending sweep failed")
	}

	ticker := time.NewTicker(stalePendingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.retentionWorker.SweepStalePending(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.log.Error().Err(err).Msg("stale pending sweep failed")
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
	if s.isDraining() {
		api.JSON(w, http.StatusServiceUnavailable, readyResponse{
			Status: "not ready",
			Reason: "server draining",
		})
		return
	}

	if s.db == nil || s.db.PingContext(r.Context()) != nil {
		api.JSON(w, http.StatusServiceUnavailable, readyResponse{
			Status: "not ready",
			Reason: "database unavailable",
		})
		return
	}

	api.JSON(w, http.StatusOK, readyResponse{Status: "ready"})
}

func (s *Server) shutdownMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isDraining() || r.URL.Path == "/api/v1/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/v1/ready" {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "server draining", http.StatusServiceUnavailable)
	})
}

// @Summary      Metrics
// @Description  Returns basic server metrics
// @Tags         system
// @Produce      json
// @Success      200  {object}  api.Response{data=server.metricsResponse}
// @Router       /metrics [get]
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	response := metricsResponse{
		UptimeSeconds: time.Since(s.startedAt).Seconds(),
		GoVersion:     runtime.Version(),
	}
	if s.cfg.SecretScan.Enabled && s.queries != nil {
		if depth, err := s.queries.CountPendingSecretScanJobs(r.Context()); err == nil {
			response.SecretScanQueueDepth = &depth
		}
	}
	api.JSON(w, http.StatusOK, response)
}
