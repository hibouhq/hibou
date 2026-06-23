package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/ws"
)

type staleScanCheckerFunc func(context.Context)

type advisoryScanCall struct {
	SnapshotID uuid.UUID
	Providers  []string
	Triggered  string
}

type advisoryScannerStub struct {
	calls chan advisoryScanCall
	err   error
}

func (s *advisoryScannerStub) RunScan(_ context.Context, snapshotID uuid.UUID, providerNames []string, triggeredBy string) (uuid.UUID, error) {
	if s.calls != nil {
		s.calls <- advisoryScanCall{
			SnapshotID: snapshotID,
			Providers:  append([]string(nil), providerNames...),
			Triggered:  triggeredBy,
		}
	}
	return uuid.New(), s.err
}

func (s *advisoryScannerStub) TriggerRescan(_ context.Context, snapshotID uuid.UUID, providerNames []string, actor audit.Entry) (uuid.UUID, error) {
	if s.calls != nil {
		s.calls <- advisoryScanCall{
			SnapshotID: snapshotID,
			Providers:  append([]string(nil), providerNames...),
			Triggered:  actor.ActorDisplay,
		}
	}
	return uuid.New(), s.err
}

func (fn staleScanCheckerFunc) Start(ctx context.Context) {
	fn(ctx)
}

func TestRunStalePendingLoopNilWorker(t *testing.T) {
	srv := &Server{}

	srv.runStalePendingLoop(context.Background())
}

func TestNewFailsWhenFilesystemArtifactStoreInitFails(t *testing.T) {
	artifactRoot := t.TempDir()
	artifactFile, err := os.CreateTemp(artifactRoot, "artifact-store-file")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := artifactFile.Close(); err != nil {
		t.Fatalf("Close artifact file: %v", err)
	}

	srv, err := New(config.Config{
		ArtifactPath: artifactFile.Name(),
		UploadWindow: 10 * time.Minute,
	}, zerolog.New(io.Discard), nil, nil, nil, nil, os.DirFS(t.TempDir()))
	if err == nil {
		t.Fatal("New() error = nil, want artifact store init failure")
	}
	if srv != nil {
		t.Fatal("srv != nil, want nil on artifact store init failure")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "initialize artifact backend \"filesystem\"") {
		t.Fatalf("New() error = %q, want filesystem backend context", got)
	}
	if !strings.Contains(err.Error(), artifactFile.Name()) {
		t.Fatalf("New() error = %q, want underlying filesystem path failure", err)
	}
}

func TestNewInitializesS3ArtifactStore(t *testing.T) {
	srv, err := New(config.Config{
		ArtifactBackend: "s3",
		AdvisoryScan: config.AdvisoryScanConfig{
			Providers: []string{"osv"},
			Interval:  6 * time.Hour,
		},
		OSVURL: "http://osv.internal",
		ArtifactS3: config.ArtifactS3Config{
			Endpoint:     "127.0.0.1:9000",
			Region:       "us-east-1",
			Bucket:       "hibou-artifacts",
			UsePathStyle: true,
			UseSSL:       false,
		},
		UploadWindow: 10 * time.Minute,
	}, zerolog.New(io.Discard), nil, nil, nil, nil, os.DirFS(t.TempDir()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.objStore == nil {
		t.Fatal("objStore = nil, want initialized S3 store")
	}
	if srv.retentionWorker == nil {
		t.Fatal("retentionWorker = nil, want non-nil")
	}
	if srv.advisoryScanner == nil {
		t.Fatal("advisoryScanner = nil, want initialized scanner")
	}
	if !reflect.DeepEqual(srv.advisoryProviders, []string{"osv"}) {
		t.Fatalf("advisoryProviders = %v, want [osv]", srv.advisoryProviders)
	}
}

func TestNewDisablesAdvisoryScanningForUnsupportedProviders(t *testing.T) {
	var logs bytes.Buffer
	artifactPath := t.TempDir()
	srv, err := New(config.Config{
		AdvisoryScan: config.AdvisoryScanConfig{
			Providers: []string{"nvd", "nope"},
			Interval:  6 * time.Hour,
		},
		ArtifactPath:  artifactPath,
		UploadWindow: 10 * time.Minute,
	}, zerolog.New(&logs), nil, nil, nil, nil, os.DirFS(t.TempDir()))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(srv.advisoryProviders) != 0 {
		t.Fatalf("advisoryProviders = %v, want empty when no providers were built", srv.advisoryProviders)
	}
	if !strings.Contains(logs.String(), "advisory scanning disabled: no supported providers are configured") {
		t.Fatalf("startup logs = %q, want advisory scanning disabled message", logs.String())
	}
	stub := &advisoryScannerStub{calls: make(chan advisoryScanCall, 1)}
	srv.advisoryScanner = stub
	srv.enqueueAdvisoryScan(uuid.New(), "system")
	select {
	case call := <-stub.calls:
		t.Fatalf("unexpected scan trigger with unsupported providers: %+v", call)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestRunAdvisoryScanPassScansLatestComponentSnapshotPerRef(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "advisory-scan-pass"),
		slug:          uniqueName(t, "advisory-scan-pass"),
		provider:      "github",
		providerID:    uniqueName(t, "advisory-scan-provider"),
		defaultBranch: "main",
	})
	mainRef, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef(main): %v", err)
	}
	releaseRef, err := srv.queries.CreateRef(context.Background(), repo.ID, "release", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef(release): %v", err)
	}
	mainSnapshot, err := srv.queries.CreateSnapshot(context.Background(), mainRef.ID, uniqueName(t, "main-old"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(main old): %v", err)
	}
	seedSnapshotComponent(t, srv, mainSnapshot.ID, "pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", "npm")
	newerMainNoComponents, err := srv.queries.CreateSnapshot(context.Background(), mainRef.ID, uniqueName(t, "main-new"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(main new): %v", err)
	}
	releaseSnapshot, err := srv.queries.CreateSnapshot(context.Background(), releaseRef.ID, uniqueName(t, "release"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(release): %v", err)
	}
	seedSnapshotComponent(t, srv, releaseSnapshot.ID, "pkg:npm/chalk@5.0.0", "chalk", "5.0.0", "npm")
	_ = newerMainNoComponents

	stub := &advisoryScannerStub{calls: make(chan advisoryScanCall, 4096)}
	srv.advisoryScanner = stub
	srv.advisoryProviders = []string{"osv"}

	srv.runAdvisoryScanPass(context.Background())
	close(stub.calls)

	var got []uuid.UUID
	for call := range stub.calls {
		got = append(got, call.SnapshotID)
		if !reflect.DeepEqual(call.Providers, []string{"osv"}) {
			t.Fatalf("providers = %v, want [osv]", call.Providers)
		}
		if call.Triggered != "system" {
			t.Fatalf("triggeredBy = %q, want system", call.Triggered)
		}
	}
	scanned := make(map[uuid.UUID]struct{}, len(got))
	for _, snapshotID := range got {
		scanned[snapshotID] = struct{}{}
	}
	if _, ok := scanned[mainSnapshot.ID]; !ok {
		t.Fatalf("scanned snapshots missing latest main snapshot with components: %v", got)
	}
	if _, ok := scanned[releaseSnapshot.ID]; !ok {
		t.Fatalf("scanned snapshots missing release snapshot with components: %v", got)
	}
	if _, ok := scanned[newerMainNoComponents.ID]; ok {
		t.Fatalf("scanned snapshots unexpectedly included newer main snapshot without components: %v", got)
	}
}

func TestNewFailsForUnknownArtifactBackend(t *testing.T) {
	srv, err := New(config.Config{
		ArtifactBackend: "bogus",
		ArtifactPath:    t.TempDir(),
		UploadWindow:    10 * time.Minute,
	}, zerolog.New(io.Discard), nil, nil, nil, nil, os.DirFS(t.TempDir()))
	if err == nil {
		t.Fatal("New() error = nil, want unknown backend failure")
	}
	if srv != nil {
		t.Fatal("srv != nil, want nil for unknown backend")
	}
	if !strings.Contains(err.Error(), "unknown artifact backend \"bogus\"") {
		t.Fatalf("New() error = %q, want unknown backend context", err)
	}
}

func TestRoutesRegisterFindingsAlias(t *testing.T) {
	t.Parallel()

	srv, _, _, _ := newDiscoveryTestServer(t)
	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	hasFindingsRoute := false
	err := chi.Walk(srv.router, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet && route == "/api/v1/orgs/{provider}/{slug}/repos/{repoSlug}/findings" {
			hasFindingsRoute = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if !hasFindingsRoute {
		t.Fatal("expected findings route alias to be registered")
	}
}

func TestRoutesRegisterComponentGraphEndpoint(t *testing.T) {
	t.Parallel()

	srv, _, _, _ := newDiscoveryTestServer(t)
	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	hasComponentGraphRoute := false
	err := chi.Walk(srv.router, func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet && route == "/api/v1/orgs/{provider}/{slug}/repos/{repoSlug}/components/graph" {
			hasComponentGraphRoute = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if !hasComponentGraphRoute {
		t.Fatal("expected component graph route to be registered")
	}
}

func TestComponentGraphRouteIsNotSwallowedByComponentsRoute(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "component-graph-route"),
		slug:          uniqueName(t, "component-graph-route"),
		provider:      "github",
		providerID:    uniqueName(t, "component-graph-route-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "route-graph-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	seedSnapshotComponent(t, srv, snapshot.ID, "pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", "npm")

	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	recorder := httptest.NewRecorder()
	srv.router.ServeHTTP(recorder, newAuthenticatedRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components/graph?ref=main"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /components/graph status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response componentGraphEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(response.Data.Nodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(response.Data.Nodes))
	}
	if strings.Contains(recorder.Body.String(), "canonical_id") {
		t.Fatalf("route returned component list payload instead of graph payload: %s", recorder.Body.String())
	}
}

func TestFindingsAliasMatchesVulnerabilitiesResponse(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "findings-alias"),
		slug:          uniqueName(t, "findings-alias"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "findings-alias-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:              "dependency",
		SnapshotID:        snapshot.ID,
		Title:             "Alias finding",
		Description:       "desc",
		PrimaryIdentifier: json.RawMessage(`{"type":"cve","value":"CVE-2026-3000"}`),
		Identifiers:       json.RawMessage(`[{"type":"cve","value":"CVE-2026-3000"}]`),
		OriginalSeverity:  dbgen.SeverityLevelHigh,
		Severity:          dbgen.SeverityLevelHigh,
		Status:            "detected",
		ScannerName:       "unit-test",
		ScannerVendor:     "hibou",
		ScannerVersion:    "1.0",
		ScannerExternalID: "scanner",
		Fingerprint:       uuid.NewString(),
	}); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}

	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	findingsRecorder := httptest.NewRecorder()
	srv.router.ServeHTTP(findingsRecorder, newAuthenticatedRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/findings?ref=main"))
	if findingsRecorder.Code != http.StatusOK {
		t.Fatalf("GET /findings status = %d, want %d", findingsRecorder.Code, http.StatusOK)
	}

	vulnerabilitiesRecorder := httptest.NewRecorder()
	srv.router.ServeHTTP(vulnerabilitiesRecorder, newAuthenticatedRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/vulnerabilities?ref=main"))
	if vulnerabilitiesRecorder.Code != http.StatusOK {
		t.Fatalf("GET /vulnerabilities status = %d, want %d", vulnerabilitiesRecorder.Code, http.StatusOK)
	}

	if findingsRecorder.Body.String() != vulnerabilitiesRecorder.Body.String() {
		t.Fatalf("alias body mismatch:\n/findings=%s\n/vulnerabilities=%s", findingsRecorder.Body.String(), vulnerabilitiesRecorder.Body.String())
	}
}

func newAuthenticatedRequest(t *testing.T, user *store.User, method, path string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	return req.WithContext(internalauth.WithUser(req.Context(), user))
}

func TestListenAndServeSkipsStaleScanLoopWhenDisabled(t *testing.T) {
	var started atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		cfg: config.Config{
			Host: "127.0.0.1",
			Port: 0,
			Background: config.BackgroundConfig{
				StaleScanEnabled: false,
			},
		},
		log:  zerolog.New(io.Discard),
		http: &http.Server{Handler: http.NewServeMux()},
	}
	srv.staleScanChecker = staleScanCheckerFunc(func(context.Context) {
		started.Add(1)
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after cancel")
	}

	if started.Load() != 0 {
		t.Fatalf("stale scan checker started %d times, want 0", started.Load())
	}
}

type closeFunc func() error

func (fn closeFunc) Close() error {
	return fn()
}

func TestShutdownClosesWebsocketListener(t *testing.T) {
	called := 0
	srv := &Server{
		log:        zerolog.New(io.Discard),
		http:       &http.Server{Handler: http.NewServeMux()},
		wsListener: closeFunc(func() error { called++; return nil }),
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if called != 1 {
		t.Fatalf("expected websocket listener to be closed once during shutdown, got %d", called)
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}
	if called != 1 {
		t.Fatalf("expected websocket listener close count to remain 1 after repeated shutdown, got %d", called)
	}
}

func TestShutdownContinuesWhenWebsocketListenerCloseFails(t *testing.T) {
	srv := &Server{
		log:        zerolog.New(io.Discard),
		http:       &http.Server{Handler: http.NewServeMux()},
		wsListener: closeFunc(func() error { return errors.New("boom") }),
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestShutdownReleasesReplicaClaims(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	srv.http = &http.Server{Handler: http.NewServeMux()}
	srv.artifactWorkerID = "shutdown-worker"
	claimExpiry := time.Now().Add(5 * time.Minute)
	if _, err := srv.db.ExecContext(context.Background(), `
		UPDATE snapshots
		SET artifact_processing_claimed_by = $2,
			artifact_processing_claim_expires_at = $3,
			artifact_processing_finished_at = NULL,
			status = 'complete'
		WHERE id = $1
	`, snapshotID, srv.artifactWorkerID, claimExpiry); err != nil {
		t.Fatalf("seed active claim: %v", err)
	}

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot.ArtifactProcessingClaimedBy != nil || snapshot.ArtifactProcessingClaimExpiresAt != nil {
		t.Fatalf("claim after shutdown = %#v / %#v, want nil", snapshot.ArtifactProcessingClaimedBy, snapshot.ArtifactProcessingClaimExpiresAt)
	}
}

func TestShutdownLeavesInFlightClaimsLeasedAfterDrainTimeout(t *testing.T) {
	srv, inFlightSnapshotID := newArtifactProcessingTestServer(t)
	srv.http = &http.Server{Handler: http.NewServeMux()}
	srv.artifactWorkerID = "shutdown-worker"
	nonInFlightSnapshotID := createAdditionalArtifactProcessingSnapshot(t, srv)

	claimExpiry := time.Now().Add(5 * time.Minute)
	for _, snapshotID := range []string{inFlightSnapshotID.String(), nonInFlightSnapshotID.String()} {
		if _, err := srv.db.ExecContext(context.Background(), `
			UPDATE snapshots
			SET artifact_processing_claimed_by = $2,
				artifact_processing_claim_expires_at = $3,
				artifact_processing_finished_at = NULL,
				status = 'complete'
			WHERE id = $1
		`, snapshotID, srv.artifactWorkerID, claimExpiry); err != nil {
			t.Fatalf("seed active claim %s: %v", snapshotID, err)
		}
	}
	if !srv.tryStartArtifactProcessing(inFlightSnapshotID) {
		t.Fatal("tryStartArtifactProcessing() = false, want true before drain")
	}

	shutdownCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err := srv.Shutdown(shutdownCtx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown() error = %v, want context.Canceled", err)
	}

	inFlightSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), inFlightSnapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(in-flight): %v", err)
	}
	if inFlightSnapshot.ArtifactProcessingClaimedBy == nil || *inFlightSnapshot.ArtifactProcessingClaimedBy != srv.artifactWorkerID {
		t.Fatalf("in-flight claim after shutdown = %#v, want preserved %q", inFlightSnapshot.ArtifactProcessingClaimedBy, srv.artifactWorkerID)
	}
	if inFlightSnapshot.ArtifactProcessingClaimExpiresAt == nil {
		t.Fatal("in-flight claim expiry after shutdown = nil, want lease preserved")
	}

	nonInFlightSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), nonInFlightSnapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(non-in-flight): %v", err)
	}
	if nonInFlightSnapshot.ArtifactProcessingClaimedBy != nil || nonInFlightSnapshot.ArtifactProcessingClaimExpiresAt != nil {
		t.Fatalf("non-in-flight claim after shutdown = %#v / %#v, want nil", nonInFlightSnapshot.ArtifactProcessingClaimedBy, nonInFlightSnapshot.ArtifactProcessingClaimExpiresAt)
	}
}

func TestProcessNextArtifactSnapshotStopsWhenDraining(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	format := "cyclonedx-json"
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", &format, nil, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)
	quarantineUnrelatedClaimableSnapshots(t, srv, snapshotID)
	srv.beginDrain()

	processed, err := srv.processNextArtifactSnapshot(context.Background())
	if err != nil {
		t.Fatalf("processNextArtifactSnapshot() error = %v", err)
	}
	if processed {
		t.Fatal("processed = true, want false while draining")
	}

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot.ArtifactProcessingClaimedBy != nil {
		t.Fatalf("claim after drain stop = %#v, want nil", snapshot.ArtifactProcessingClaimedBy)
	}
}

func TestTryStartArtifactProcessingStopsWhenDraining(t *testing.T) {
	srv := &Server{log: zerolog.New(io.Discard)}
	srv.beginDrain()
	if srv.tryStartArtifactProcessing(uuid.New()) {
		t.Fatal("tryStartArtifactProcessing() = true, want false while draining")
	}
	if err := srv.waitForActiveArtifacts(context.Background()); err != nil {
		t.Fatalf("waitForActiveArtifacts() error = %v", err)
	}
}

func TestHandleReadyReturnsServiceUnavailableWhileDraining(t *testing.T) {
	srv := &Server{log: zerolog.New(io.Discard)}
	srv.beginDrain()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ready", nil)
	rec := httptest.NewRecorder()

	srv.handleReady(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "server draining") {
		t.Fatalf("body = %q, want drain reason", rec.Body.String())
	}
}

func TestNewClosesWebsocketListenerOnStartupFailure(t *testing.T) {
	originalBridgeFactory := newBridgeListener
	defer func() {
		newBridgeListener = originalBridgeFactory
	}()

	closed := 0
	stubListener := closeFunc(func() error {
		closed++
		return nil
	})
	newBridgeListener = func(_ string, _ string, _ func(ws.Envelope), _ zerolog.Logger) (closeableListener, error) {
		return stubListener, nil
	}

	srv, err := New(config.Config{
		DatabaseURL:     "postgres://example",
		ArtifactBackend: "bogus",
		UploadWindow:    10 * time.Minute,
	}, zerolog.New(io.Discard), &sql.DB{}, nil, nil, nil, os.DirFS(t.TempDir()))
	if err == nil {
		t.Fatal("New() error = nil, want startup failure")
	}
	if srv != nil {
		t.Fatal("srv != nil, want nil on startup failure")
	}
	if closed != 1 {
		t.Fatalf("listener close count = %d, want 1 on startup failure", closed)
	}
}

func createAdditionalArtifactProcessingSnapshot(t *testing.T, srv *Server) uuid.UUID {
	t.Helper()
	refRow := srv.db.QueryRowContext(context.Background(), `SELECT repo_id FROM refs ORDER BY created_at ASC LIMIT 1`)
	var repoID uuid.UUID
	if err := refRow.Scan(&repoID); err != nil {
		t.Fatalf("load repository for extra snapshot: %v", err)
	}
	repo, err := srv.queries.GetRepositoryByID(context.Background(), repoID)
	if err != nil {
		t.Fatalf("GetRepositoryByID: %v", err)
	}
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, uniqueName(t, "main"), store.RefTypeBranch, nil, nil, stringPtrForProcessingTest(uniqueName(t, "sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "commit"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	return snapshot.ID
}
