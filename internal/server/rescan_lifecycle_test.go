package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/scanner"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func newRescanFixture(t *testing.T) (*Server, *store.Organization, *store.Repository, *store.Snapshot, *store.User) {
	t.Helper()
	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name: uniqueName(t, "fixture"), slug: uniqueName(t, "fixture"),
		provider: "github", providerID: uniqueName(t, "provider"), defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "fixture", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	seedSnapshotComponent(t, srv, snapshot.ID, "pkg:npm/fixture@1.0.0", "fixture", "1.0.0", "npm")
	srv.advisoryProviders = []string{"osv"}
	srv.advisoryScanSlots = make(chan struct{}, 1)
	return srv, org, repo, snapshot, admin
}

func TestComponentRescanAcceptedBeforeExecutionAndSurvivesRequest(t *testing.T) {
	srv, org, repo, snapshot, admin := newRescanFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.lifecycleCtx = ctx
	t.Cleanup(func() {
		cancel()
		srv.advisoryScanTasks.Wait()
	})
	service := scanner.New(srv.queries, nil, nil, nil, nil, srv.log)
	started := make(chan context.Context, 1)
	release := make(chan struct{})
	defer close(release)
	srv.advisoryScanner = &advisoryScannerStub{
		queueRescan: service.QueueRescan,
		runRescan: func(ctx context.Context, queued dbgen.Scan) (uuid.UUID, error) {
			started <- ctx
			select {
			case <-release:
			case <-ctx.Done():
			}
			return queued.ID, context.Canceled
		},
	}
	request := newRepoRequest(t, admin, http.MethodPost, "/?ref=main", "github", org.Slug, repo.Slug)
	requestCtx, cancelRequest := context.WithCancel(request.Context())
	defer cancelRequest()
	recorder := httptest.NewRecorder()
	srv.handleTriggerComponentScan(recorder, request.WithContext(requestCtx))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			ScanID uuid.UUID `json:"scan_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	queued, err := dbgen.New(srv.db).GetScanByID(ctx, response.Data.ScanID)
	if err != nil || queued.SnapshotID != snapshot.ID || queued.Status != "pending" {
		t.Fatalf("queued=%+v err=%v", queued, err)
	}
	cancelRequest()
	select {
	case runCtx := <-started:
		if runCtx.Err() != nil {
			t.Fatalf("background inherited request cancellation: %v", runCtx.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("background rescan did not start")
	}
	conflict := httptest.NewRecorder()
	srv.handleTriggerComponentScan(conflict, newRepoRequest(t, admin, http.MethodPost, "/?ref=main", "github", org.Slug, repo.Slug))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	cancel()
	srv.advisoryScanTasks.Wait()
	queued, err = dbgen.New(srv.db).GetScanByID(context.Background(), queued.ID)
	if err != nil || queued.Status != "cancelled" || !queued.CompletedAt.Valid {
		t.Fatalf("shutdown cleanup=%+v err=%v", queued, err)
	}
}

func TestQueuedAdvisoryScanCancellationAndPanicCleanup(t *testing.T) {
	for _, panicWorker := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiting for slot", true: "panic"}[panicWorker], func(t *testing.T) {
			srv, _, _, snapshot, _ := newRescanFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv.lifecycleCtx = ctx
			t.Cleanup(func() {
				cancel()
				srv.advisoryScanTasks.Wait()
			})
			queued, err := srv.queries.CreateScan(ctx, dbgen.CreateScanParams{SnapshotID: snapshot.ID, Status: "pending", ProvidersRequested: []string{"osv"}, TriggeredBy: "system"})
			if err != nil {
				t.Fatal(err)
			}

			if !panicWorker {
				srv.advisoryScanSlots <- struct{}{}
			}
			srv.runQueuedAdvisoryScanInBackground(queued, func(ctx context.Context) (uuid.UUID, error) {
				if panicWorker {
					panic("fixture panic")
				}
				t.Error("cancelled queued scan acquired an occupied slot")
				return uuid.Nil, errors.New("unexpected execution")
			})
			if !panicWorker {
				cancel()
			}
			srv.advisoryScanTasks.Wait()
			stored, err := dbgen.New(srv.db).GetScanByID(context.Background(), queued.ID)
			want := "cancelled"
			if panicWorker {
				want = "failed"
			}
			if err != nil || stored.Status != want || !stored.CompletedAt.Valid {
				t.Fatalf("stored=%+v err=%v, want %s", stored, err, want)
			}
			wantSlots := 0
			if !panicWorker {
				wantSlots = 1
			}
			if len(srv.advisoryScanSlots) != wantSlots {
				t.Fatal("scan slot leaked")
			}
		})
	}
}

func TestAdvisoryScanPassUsesBoundedParallelismAndReleasesCancelledSlots(t *testing.T) {
	srv, _, repo, _, _ := newRescanFixture(t)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "other", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "fixture", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	seedSnapshotComponent(t, srv, snapshot.ID, "pkg:npm/fixture@1.0.0", "fixture", "1.0.0", "npm")
	srv.advisoryScanSlots = make(chan struct{}, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{}, 2)
	srv.advisoryScanner = &advisoryScannerStub{
		runScan: func(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
			started <- struct{}{}
			<-ctx.Done()
			return id, ctx.Err()
		},
	}
	done := make(chan error, 1)
	go func() { done <- srv.advisoryScanPass(ctx) }()
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("pass did not run two scans concurrently")
		}
	}
	if len(srv.advisoryScanSlots) != 2 {
		t.Fatal("scans did not occupy the shared slots")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled pass error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pass did not stop after cancellation")
	}
	if len(srv.advisoryScanSlots) != 0 {
		t.Fatal("cancelled pass leaked shared slots")
	}
}

func TestOrgComponentRescanQueuesAndReportsSkipped(t *testing.T) {
	srv, org, repo, snapshot, admin := newRescanFixture(t)
	ctx := context.Background()
	if _, err := srv.queries.CreateScan(ctx, dbgen.CreateScanParams{SnapshotID: snapshot.ID, Status: "pending", ProvidersRequested: []string{"osv"}, TriggeredBy: "system"}); err != nil {
		t.Fatal(err)
	}
	otherRepo := createRepository(t, srv, org, repoSeed{
		name: uniqueName(t, "other"), slug: uniqueName(t, "other"),
		provider: "github", providerID: uniqueName(t, "provider"), defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(ctx, otherRepo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherSnapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "fixture", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	service := scanner.New(srv.queries, nil, nil, nil, nil, srv.log)
	srv.advisoryScanner = &advisoryScannerStub{
		queueRescan: service.QueueRescan,
		runRescan: func(ctx context.Context, queued dbgen.Scan) (uuid.UUID, error) {
			return queued.ID, context.Canceled
		},
	}
	t.Cleanup(srv.advisoryScanTasks.Wait)
	recorder := httptest.NewRecorder()
	srv.handleTriggerOrgComponentScan(recorder, newOrgRequest(t, admin, http.MethodPost, "/", "github", org.Slug))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data orgComponentScanResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Scans) != 1 || response.Data.Scans[0].Repo != otherRepo.Slug ||
		len(response.Data.Skipped) != 1 || response.Data.Skipped[0] != repo.Slug || len(response.Data.Failed) != 0 {
		t.Fatalf("response=%+v", response.Data)
	}
	queued, err := dbgen.New(srv.db).GetScanByID(ctx, response.Data.Scans[0].ScanID)
	if err != nil || queued.SnapshotID != otherSnapshot.ID {
		t.Fatalf("queued=%+v err=%v", queued, err)
	}
	cooldown := httptest.NewRecorder()
	srv.handleTriggerOrgComponentScan(cooldown, newOrgRequest(t, admin, http.MethodPost, "/", "github", org.Slug))
	if cooldown.Code != http.StatusTooManyRequests || cooldown.Header().Get("Retry-After") == "" {
		t.Fatalf("cooldown status=%d retry-after=%q", cooldown.Code, cooldown.Header().Get("Retry-After"))
	}
}

func TestOrgComponentRescanAllActiveReturnsConflict(t *testing.T) {
	srv, org, _, snapshot, admin := newRescanFixture(t)
	ctx := context.Background()
	if _, err := srv.queries.CreateScan(ctx, dbgen.CreateScanParams{SnapshotID: snapshot.ID, Status: "pending", ProvidersRequested: []string{"osv"}, TriggeredBy: "system"}); err != nil {
		t.Fatal(err)
	}
	service := scanner.New(srv.queries, nil, nil, nil, nil, srv.log)
	srv.advisoryScanner = &advisoryScannerStub{queueRescan: service.QueueRescan}
	recorder := httptest.NewRecorder()
	srv.handleTriggerOrgComponentScan(recorder, newOrgRequest(t, admin, http.MethodPost, "/", "github", org.Slug))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("all active status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
