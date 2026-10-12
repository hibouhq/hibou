package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scancoverage"
	"github.com/hibouhq/hibou/internal/store"
)

func cellFor(cells []scancoverage.Cell, scanner string) scancoverage.Cell {
	for _, cell := range cells {
		if cell.ScannerID == scanner {
			return cell
		}
	}
	return scancoverage.Cell{}
}

// Configured is not observed: a required scanner that never ran is a gap;
// an unbound report does not satisfy a blocking requirement; a PR head
// without the required report fails the coverage check.
func TestScanCoverageInventoryAndPRCheck(t *testing.T) {
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
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo.ProviderID = "acme/app"
	ctx := context.Background()
	if _, err := srv.detectRepoApplicability(ctx, repo, "main", "head-sha"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.queries.UpsertScannerRequirement(ctx, org.ID, store.ScannerRequirement{Language: "java", Capability: "bytecode-security", Enforcement: "blocking"}, &admin.ID); err != nil {
		t.Fatal(err)
	}

	cells, err := srv.refreshRepoScanCoverage(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	spotbugs := cellFor(cells, "spotbugs-findsecbugs")
	if !spotbugs.Required || spotbugs.State != scancoverage.StateMissing || !spotbugs.Gap() {
		t.Fatalf("required scanner that never ran = %+v", spotbugs)
	}

	// An unbound SpotBugs report on the default branch: ran, not verified.
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "main", store.RefTypeBranch)
	if err != nil || ref == nil {
		ref, err = srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "head-sha", store.SnapshotStatusComplete)
	recordRun(t, srv, snapshot.ID, store.ProducerRunInput{Producer: "spotbugs", Scope: "full", ScopeDeclared: true, Outcome: "completed"})
	cells, err = srv.refreshRepoScanCoverage(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := cellFor(cells, "spotbugs-findsecbugs"); got.State != scancoverage.StateUnverified {
		t.Fatalf("unbound report under a blocking requirement = %+v", got)
	}
	matrix, err := srv.queries.ListOrgScanCoverage(ctx, org.ID, store.OrgScanCoverageFilter{RequiredOnly: true, Limit: 10})
	if err != nil || len(matrix) != 1 || matrix[0].State != scancoverage.StateUnverified || matrix[0].RepoSlug != repo.Slug {
		t.Fatalf("persisted matrix = %+v, %v", matrix, err)
	}

	// A PR head with no SpotBugs report fails the check.
	prRef, _ := srv.queries.CreateRef(ctx, repo.ID, "refs/pull/7/merge", store.RefTypeBranch, nil, nil, nil)
	prSnapshot, _ := srv.queries.CreateSnapshot(ctx, prRef.ID, "pr-sha", store.SnapshotStatusComplete)
	blocking, _, err := srv.prCoverageCheck(ctx, repo.ID, prSnapshot.ID)
	if err != nil || len(blocking) != 1 || !strings.Contains(blocking[0], "spotbugs-findsecbugs") {
		t.Fatalf("PR coverage check = %v, %v", blocking, err)
	}
}

func callBulkScannerSetting(t *testing.T, srv *Server, user *store.User, org *store.Organization, body string) bulkScannerSettingResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/scanner-settings/bulk", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	req = req.WithContext(context.WithValue(internalauth.WithUser(req.Context(), user), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	srv.handleBulkScannerSetting(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("bulk = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data bulkScannerSettingResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

// Bulk changes preview first, never disable a required scanner, and apply
// only to repositories whose effective state changes.
func TestBulkScannerSetting(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	catalog, _ := scancatalog.Load()
	srv.scanCatalog = catalog
	srv.forges = map[string]forge.Provider{"github": &treeTestForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}, listing: &forge.TreeListing{
		Paths: []string{"pom.xml", "src/main/java/App.java"},
	}}}
	ctx := context.Background()
	repos := []*store.Repository{createUploadTestRepository(t, srv, org), createUploadTestRepository(t, srv, org)}
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	for _, repo := range repos {
		repo.ProviderID = "acme/" + repo.Slug
		if _, err := srv.detectRepoApplicability(ctx, repo, "main", "sha"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.queries.UpsertScannerRequirement(ctx, org.ID, store.ScannerRequirement{Language: "java", Capability: "bytecode-security", Enforcement: "blocking"}, &admin.ID); err != nil {
		t.Fatal(err)
	}
	for _, repo := range repos {
		if _, err := srv.refreshRepoScanCoverage(ctx, repo); err != nil {
			t.Fatal(err)
		}
	}

	preview := callBulkScannerSetting(t, srv, admin, org, `{"scanner_id":"opengrep","mode":"disabled","dry_run":true}`)
	if len(preview.Changes) != 2 || preview.Applied {
		t.Fatalf("preview = %+v", preview)
	}
	if settings, _ := srv.queries.ListRepoScannerSettings(ctx, repos[0].ID); len(settings) != 0 {
		t.Fatal("a dry run changes nothing")
	}
	kept := callBulkScannerSetting(t, srv, admin, org, `{"scanner_id":"spotbugs-findsecbugs","mode":"disabled"}`)
	if len(kept.Changes) != 0 || len(kept.Kept) != 2 {
		t.Fatalf("required scanner must be kept: %+v", kept)
	}
	applied := callBulkScannerSetting(t, srv, admin, org, `{"scanner_id":"opengrep-interfile","mode":"enabled"}`)
	if !applied.Applied || len(applied.Changes) != 2 {
		t.Fatalf("enable pre-release = %+v", applied)
	}
	if settings, _ := srv.queries.ListRepoScannerSettings(ctx, repos[1].ID); len(settings) != 1 || settings[0].Mode != "enabled" {
		t.Fatalf("settings = %+v", settings)
	}
}
