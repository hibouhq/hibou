package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

type repositoryListResponse struct {
	Data       []repositoryInventoryEntry `json:"data"`
	Pagination struct {
		Page    int `json:"page"`
		PerPage int `json:"per_page"`
		Total   int `json:"total"`
	} `json:"pagination"`
}

type dashboardResponse struct {
	Data orgDashboardResponse `json:"data"`
}

type repoSeed struct {
	name           string
	slug           string
	provider       string
	providerID     string
	defaultBranch  string
	latestCommit   string
	snapshotCommit string
}

func TestHandleListReposUsesInventoryAndKeepsLegacyRepos(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)

	createInventoryRepo(t, srv, org, "inventory-discovered", false)
	activeRepo := createRepositoryWithSnapshot(t, srv, org, repoSeed{
		name:           "inventory-active",
		slug:           "inventory-active",
		provider:       "github",
		providerID:     org.Slug + "/inventory-active",
		defaultBranch:  "main",
		latestCommit:   "current-sha",
		snapshotCommit: "current-sha",
	})
	createInventoryRepo(t, srv, org, "inventory-active", false)
	legacyRepo := createRepositoryWithSnapshot(t, srv, org, repoSeed{
		name:           "legacy-repo",
		slug:           "legacy-repo",
		provider:       "github",
		providerID:     "legacy/manual-only",
		defaultBranch:  "main",
		latestCommit:   "new-sha",
		snapshotCommit: "old-sha",
	})
	createInventoryRepo(t, srv, org, "inventory-archived", true)

	recorder := httptest.NewRecorder()
	srv.handleListRepos(recorder, newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos", "github", org.Slug))

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleListRepos() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response repositoryListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Pagination.Total != 4 {
		t.Fatalf("pagination total = %d, want 4", response.Pagination.Total)
	}

	entriesByProviderID := inventoryEntriesByProviderID(response.Data)
	assertRepositoryEntry(t, entriesByProviderID, org.Slug+"/inventory-discovered", repoLifecycleStatusDiscovered, false)
	active := assertRepositoryEntry(t, entriesByProviderID, activeRepo.ProviderID, repoLifecycleStatusActive, true)
	if active.ID == nil || *active.ID != activeRepo.ID {
		t.Fatal("expected enrolled inventory repository to retain repository id")
	}
	if active.Outdated {
		t.Fatal("expected current snapshot to keep outdated=false")
	}
	legacy := assertRepositoryEntry(t, entriesByProviderID, legacyRepo.ProviderID, repoLifecycleStatusActive, true)
	if legacy.FullName != legacyRepo.ProviderID {
		t.Fatalf("legacy full_name = %q, want %q", legacy.FullName, legacyRepo.ProviderID)
	}
	if legacy.HTMLURL != "https://github.com/legacy/manual-only" {
		t.Fatalf("legacy html_url = %q, want %q", legacy.HTMLURL, "https://github.com/legacy/manual-only")
	}
	if !legacy.Outdated {
		t.Fatal("expected mismatched snapshot to set outdated=true while status stays active")
	}
	if legacy.LastScanned == nil {
		t.Fatal("expected last_scanned for repo with snapshot")
	}
	assertRepositoryEntry(t, entriesByProviderID, org.Slug+"/inventory-archived", repoLifecycleStatusArchived, false)
}

func TestHandleGetOrgDashboardUsesInventoryCoverage(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)

	createInventoryRepo(t, srv, org, "inventory-discovered", false)
	createInventoryRepo(t, srv, org, "inventory-no-scan", false)
	createRepository(t, srv, org, repoSeed{
		name:          "inventory-no-scan",
		slug:          "inventory-no-scan",
		provider:      "github",
		providerID:    org.Slug + "/inventory-no-scan",
		defaultBranch: "main",
	})
	createInventoryRepo(t, srv, org, "inventory-active", false)
	createRepositoryWithSnapshot(t, srv, org, repoSeed{
		name:           "inventory-active",
		slug:           "inventory-active",
		provider:       "github",
		providerID:     org.Slug + "/inventory-active",
		defaultBranch:  "main",
		latestCommit:   "current-sha",
		snapshotCommit: "current-sha",
	})
	createInventoryRepo(t, srv, org, "inventory-outdated", false)
	createRepositoryWithSnapshot(t, srv, org, repoSeed{
		name:           "inventory-outdated",
		slug:           "inventory-outdated",
		provider:       "github",
		providerID:     org.Slug + "/inventory-outdated",
		defaultBranch:  "main",
		latestCommit:   "new-sha",
		snapshotCommit: "old-sha",
	})
	createInventoryRepo(t, srv, org, "inventory-archived", true)

	recorder := httptest.NewRecorder()
	srv.handleGetOrgDashboard(recorder, newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/dashboard", "github", org.Slug))

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetOrgDashboard() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response dashboardResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Data.Coverage.TotalAccessible != 5 {
		t.Fatalf("coverage total_accessible = %d, want 5", response.Data.Coverage.TotalAccessible)
	}
	if response.Data.Coverage.Enrolled != 3 {
		t.Fatalf("coverage enrolled = %d, want 3", response.Data.Coverage.Enrolled)
	}
	if response.Data.Coverage.Discovered != 2 {
		t.Fatalf("coverage discovered = %d, want 2", response.Data.Coverage.Discovered)
	}
	if response.Data.Coverage.Active != 2 {
		t.Fatalf("coverage active = %d, want 2", response.Data.Coverage.Active)
	}
	if response.Data.Coverage.Archived != 1 {
		t.Fatalf("coverage archived = %d, want 1", response.Data.Coverage.Archived)
	}
	if response.Data.Coverage.Outdated != 1 {
		t.Fatalf("coverage outdated = %d, want 1", response.Data.Coverage.Outdated)
	}

	statuses := make(map[string]repoDashboardEntryResponse, len(response.Data.Repos))
	for _, entry := range response.Data.Repos {
		statuses[entry.ProviderID] = entry
	}
	if statuses[org.Slug+"/inventory-discovered"].Status != string(repoLifecycleStatusDiscovered) {
		t.Fatalf("dashboard discovered status = %q, want %q", statuses[org.Slug+"/inventory-discovered"].Status, repoLifecycleStatusDiscovered)
	}
	if statuses[org.Slug+"/inventory-no-scan"].Status != string(repoLifecycleStatusDiscovered) {
		t.Fatalf("dashboard no-scan status = %q, want %q", statuses[org.Slug+"/inventory-no-scan"].Status, repoLifecycleStatusDiscovered)
	}
	if statuses[org.Slug+"/inventory-active"].Status != string(repoLifecycleStatusActive) {
		t.Fatalf("dashboard active status = %q, want %q", statuses[org.Slug+"/inventory-active"].Status, repoLifecycleStatusActive)
	}
	if statuses[org.Slug+"/inventory-outdated"].Status != string(repoLifecycleStatusActive) {
		t.Fatalf("dashboard outdated status = %q, want %q", statuses[org.Slug+"/inventory-outdated"].Status, repoLifecycleStatusActive)
	}
	if !statuses[org.Slug+"/inventory-outdated"].Outdated {
		t.Fatal("dashboard outdated repository should keep status active and outdated=true")
	}
	if statuses[org.Slug+"/inventory-archived"].Status != string(repoLifecycleStatusArchived) {
		t.Fatalf("dashboard archived status = %q, want %q", statuses[org.Slug+"/inventory-archived"].Status, repoLifecycleStatusArchived)
	}
}

func newOrgRequest(t *testing.T, user *store.User, method, path, provider, slug string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	ctx := internalauth.WithUser(req.Context(), user)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", provider)
	rctx.URLParams.Add("slug", slug)
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

func createInventoryRepo(t *testing.T, srv *Server, org *store.Organization, name string, archived bool) *store.ForgeRepository {
	t.Helper()

	repo, err := srv.queries.UpsertForgeRepository(context.Background(), store.ForgeRepository{
		Provider:      org.Provider,
		AccountLogin:  org.Slug,
		Owner:         org.Slug,
		Name:          name,
		FullName:      org.Slug + "/" + name,
		Private:       true,
		DefaultBranch: "main",
		HTMLURL:       "https://github.com/" + org.Slug + "/" + name,
		Archived:      archived,
	})
	if err != nil {
		t.Fatalf("UpsertForgeRepository(%s): %v", name, err)
	}
	if repo == nil || repo.Repository == nil {
		t.Fatalf("UpsertForgeRepository(%s) returned nil repository", name)
	}
	return repo.Repository
}

func inventoryEntriesByProviderID(entries []repositoryInventoryEntry) map[string]repositoryInventoryEntry {
	entriesByProviderID := make(map[string]repositoryInventoryEntry, len(entries))
	for _, entry := range entries {
		entriesByProviderID[entry.ProviderID] = entry
	}
	return entriesByProviderID
}

func assertRepositoryEntry(t *testing.T, entries map[string]repositoryInventoryEntry, providerID string, status repoLifecycleStatus, enrolled bool) repositoryInventoryEntry {
	t.Helper()

	entry, ok := entries[providerID]
	if !ok {
		t.Fatalf("expected repository %q in response", providerID)
	}
	if entry.Enrolled != enrolled {
		t.Fatalf("repository %q enrolled = %v, want %v", providerID, entry.Enrolled, enrolled)
	}
	if entry.Status != status {
		t.Fatalf("repository %q status = %q, want %q", providerID, entry.Status, status)
	}
	return entry
}

func createRepository(t *testing.T, srv *Server, org *store.Organization, seed repoSeed) *store.Repository {
	t.Helper()

	repo, err := srv.queries.CreateRepository(context.Background(), org.ID, nil, seed.name, seed.slug, seed.provider, seed.providerID, seed.defaultBranch, "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository(%s): %v", seed.name, err)
	}
	return repo
}

func createRepositoryWithSnapshot(t *testing.T, srv *Server, org *store.Organization, seed repoSeed) *store.Repository {
	t.Helper()

	repo := createRepository(t, srv, org, seed)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, seed.defaultBranch, store.RefTypeBranch, nil, nil, &seed.latestCommit)
	if err != nil {
		t.Fatalf("CreateRef(%s): %v", seed.name, err)
	}
	if _, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, seed.snapshotCommit, store.SnapshotStatusComplete); err != nil {
		t.Fatalf("CreateSnapshot(%s): %v", seed.name, err)
	}
	return repo
}
