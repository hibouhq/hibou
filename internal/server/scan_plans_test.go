package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanplan"
	"github.com/hibouhq/hibou/internal/store"
)

// A plan is built from the commit's file list and stored; a report uploaded
// with plan_id/plan_job_id takes the job's planned scope as its declaration
// and is bound to the job; a binding for another commit is refused.
func TestScanPlanAndBoundUpload(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	catalog, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	srv.scanCatalog = catalog
	fake := &treeTestForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}, listing: &forge.TreeListing{
		Paths: []string{"java/pom.xml", "java/src/main/java/App.java", "README.md"},
	}}
	srv.forges = map[string]forge.Provider{"github": fake}
	repo := createUploadTestRepository(t, srv, org)
	if _, err := srv.db.ExecContext(context.Background(), `UPDATE repositories SET provider_id = 'acme/app' WHERE id = $1`, repo.ID); err != nil {
		t.Fatal(err)
	}

	body := `{"ref":"main","commit_sha":"test-sha","runner":{"os":"linux","arch":"amd64"}}`
	req := httptest.NewRequest(http.MethodPost, "/scan-plans", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	routeCtx.URLParams.Add("repoSlug", repo.Slug)
	req = req.WithContext(context.WithValue(internalauth.WithUser(req.Context(), admin), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	srv.handleCreateScanPlan(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create plan = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data scanPlanResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.ID == nil || envelope.Data.Plan.CommitSHA != "test-sha" || fake.listRef != "test-sha" {
		t.Fatalf("plan = %+v (listed %s)", envelope.Data, fake.listRef)
	}
	var spotbugs scanplan.Job
	for _, job := range envelope.Data.Plan.Jobs {
		if job.ScannerID == "spotbugs-findsecbugs" {
			spotbugs = job
		}
	}
	if spotbugs.Status != scanplan.JobReady || spotbugs.Scope != "partial" {
		t.Fatalf("spotbugs job = %+v", spotbugs)
	}

	bound := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"plan_id": envelope.Data.ID.String(), "plan_job_id": spotbugs.ID,
	}))
	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), mustParseUUID(t, bound.SnapshotID))
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("artifacts = %+v, %v", artifacts, err)
	}
	artifact := artifacts[0]
	if artifact.PlanID == nil || *artifact.PlanID != *envelope.Data.ID || derefString(artifact.PlanJobID) != spotbugs.ID {
		t.Fatalf("artifact not bound to the plan job: %+v", artifact)
	}
	if derefString(artifact.Scope) != store.ProducerScopePartial || len(artifact.ScopePaths) != 1 || artifact.ScopePaths[0] != "java" {
		t.Fatalf("planned scope not declared: %+v", artifact)
	}

	other := uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"plan_id": envelope.Data.ID.String(), "plan_job_id": spotbugs.ID, "commit_sha": "another-sha",
	})
	if rec := performUploadAutoRecorder(t, srv, admin, other); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "another commit") {
		t.Fatalf("binding to another commit = %d: %s", rec.Code, rec.Body.String())
	}
}

func mustParseUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(value)
	if err != nil {
		t.Fatalf("uuid %q: %v", value, err)
	}
	return id
}

func createPlanForTest(t *testing.T, srv *Server, user *store.User, org *store.Organization, repoSlug string) scanplan.Plan {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/scan-plans", strings.NewReader(`{"commit_sha":"test-sha","runner":{"os":"linux","arch":"amd64"},"dry_run":true}`))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	routeCtx.URLParams.Add("repoSlug", repoSlug)
	req = req.WithContext(context.WithValue(internalauth.WithUser(req.Context(), user), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	srv.handleCreateScanPlan(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dry-run plan = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data scanPlanResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data.Plan
}

func planHasScanner(plan scanplan.Plan, id string) bool {
	for _, job := range plan.Jobs {
		if job.ScannerID == id {
			return true
		}
	}
	return false
}

// ADR-035 §5: a repo cannot disable what the org requires; an approved,
// unexpired exception can.
func TestScanPlanFollowsOrgRequirements(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	catalog, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	srv.scanCatalog = catalog
	srv.forges = map[string]forge.Provider{"github": &treeTestForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}, listing: &forge.TreeListing{
		Paths: []string{"pom.xml", "src/main/java/App.java"},
	}}}
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	if _, err := srv.db.ExecContext(ctx, `UPDATE repositories SET provider_id = 'acme/app' WHERE id = $1`, repo.ID); err != nil {
		t.Fatal(err)
	}

	if err := srv.queries.UpsertRepoScannerSetting(ctx, repo.ID, "spotbugs-findsecbugs", "disabled", &admin.ID); err != nil {
		t.Fatal(err)
	}
	if planHasScanner(createPlanForTest(t, srv, admin, org, repo.Slug), "spotbugs-findsecbugs") {
		t.Fatal("a disabled, not required scanner must not be planned")
	}

	requirement, err := srv.queries.UpsertScannerRequirement(ctx, org.ID, store.ScannerRequirement{Language: "java", Capability: "bytecode-security", Enforcement: "blocking"}, &admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !planHasScanner(createPlanForTest(t, srv, admin, org, repo.Slug), "spotbugs-findsecbugs") {
		t.Fatal("a required scanner is planned even when the repo disabled it")
	}

	exception, err := srv.queries.CreateCoverageException(ctx, store.CoverageException{
		RepoID: repo.ID, RequirementID: requirement.ID, Scope: ".", Reason: "generated code only", ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !planHasScanner(createPlanForTest(t, srv, admin, org, repo.Slug), "spotbugs-findsecbugs") {
		t.Fatal("a requested (not approved) exception waives nothing")
	}
	if decided, err := srv.queries.DecideCoverageException(ctx, org.ID, exception.ID, "approved", &admin.ID); err != nil || decided == nil {
		t.Fatalf("approve = %+v, %v", decided, err)
	}
	if planHasScanner(createPlanForTest(t, srv, admin, org, repo.Slug), "spotbugs-findsecbugs") {
		t.Fatal("an approved exception waives the requirement; the repo's disabled applies again")
	}
}
