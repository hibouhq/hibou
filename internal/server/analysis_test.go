package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type componentListResponse struct {
	Data []componentWithVulnsResponse `json:"data"`
}

type componentGraphEnvelope struct {
	Data componentGraphResponse `json:"data"`
}

type findingsListResponse struct {
	Data       []store.Vulnerability `json:"data"`
	Pagination struct {
		Page    int `json:"page"`
		PerPage int `json:"per_page"`
		Total   int `json:"total"`
	} `json:"pagination"`
}

type refSummaryEnvelope struct {
	Data refSummaryResponse `json:"data"`
}

type enhancedRefsResponse struct {
	Data       []store.EnhancedRef `json:"data"`
	Pagination struct {
		Page    int `json:"page"`
		PerPage int `json:"per_page"`
		Total   int `json:"total"`
	} `json:"pagination"`
}

func TestResolveSnapshotForRepoPrefersLatestFinishedSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	completeSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "complete-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(complete): %v", err)
	}
	if _, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "pending-sha", store.SnapshotStatusPending); err != nil {
		t.Fatalf("CreateSnapshot(pending): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepo(newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug), repo, "main")
	if err != nil {
		t.Fatalf("resolveSnapshotForRepo: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != completeSnapshot.ID {
		t.Fatalf("snapshot id = %s, want %s", snapshot.ID, completeSnapshot.ID)
	}
}

func TestResolveSnapshotForRepoFallsBackToLatestPendingSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	pendingSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "pending-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(pending): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepo(newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug), repo, "main")
	if err != nil {
		t.Fatalf("resolveSnapshotForRepo: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != pendingSnapshot.ID {
		t.Fatalf("snapshot id = %s, want %s", snapshot.ID, pendingSnapshot.ID)
	}
}

func TestResolveSnapshotForComponentsViewPrefersOlderComponentSnapshotOverNewerVulnerabilityOnlySnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	componentSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "data-sha", store.SnapshotStatusFailed)
	if err != nil {
		t.Fatalf("CreateSnapshot(data): %v", err)
	}
	seedSnapshotComponent(t, srv, componentSnapshot.ID, "pkg:gomod/github.com/example/lib", "example-lib", "1.2.3", "go")
	vulnerabilityOnlySnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "vuln-only-sha", store.SnapshotStatusFailed)
	if err != nil {
		t.Fatalf("CreateSnapshot(vuln only): %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "secret",
		SnapshotID:             vulnerabilityOnlySnapshot.ID,
		Title:                  "Secret finding",
		Description:            "desc",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "secret-1",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            "unit-test",
		ScannerVendor:          "hibou",
		ScannerVersion:         "1.0",
		ScannerExternalID:      "scanner",
		Fingerprint:            uuid.NewString(),
	}); err != nil {
		t.Fatalf("CreateVulnerability(secret): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepoWithFallback(
		newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug),
		repo,
		"main",
		srv.queries.GetLatestSnapshotWithComponentsByRef,
	)
	if err != nil {
		t.Fatalf("resolveSnapshotForRepoWithFallback: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != componentSnapshot.ID {
		t.Fatalf("snapshot id = %s, want component snapshot %s instead of newer vulnerability-only snapshot %s", snapshot.ID, componentSnapshot.ID, vulnerabilityOnlySnapshot.ID)
	}
	components, err := srv.queries.ListComponentsBySnapshot(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatalf("ListComponentsBySnapshot: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("component count = %d, want 1", len(components))
	}
	if components[0].Name != "example-lib" {
		t.Fatalf("component name = %q, want example-lib", components[0].Name)
	}
}

func TestResolveSnapshotForFindingsViewPrefersLatestVulnerabilityDataWhenNoCompleteSnapshotExists(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	dataSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "vuln-data-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(data): %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "dependency",
		SnapshotID:             dataSnapshot.ID,
		Title:                  "Known issue",
		Description:            "desc",
		PrimaryIdentifierKind:  "cve",
		PrimaryIdentifierValue: "CVE-2026-0001",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            "unit-test",
		ScannerVendor:          "hibou",
		ScannerVersion:         "1.0",
		ScannerExternalID:      "scanner",
		Fingerprint:            uuid.NewString(),
	}); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}
	latestFailedSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "failed-empty-sha", store.SnapshotStatusFailed)
	if err != nil {
		t.Fatalf("CreateSnapshot(failed empty): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepoWithFallback(
		newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug),
		repo,
		"main",
		srv.queries.GetLatestSnapshotWithVulnerabilitiesByRef,
	)
	if err != nil {
		t.Fatalf("resolveSnapshotForRepoWithFallback: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != dataSnapshot.ID {
		t.Fatalf("snapshot id = %s, want vulnerability snapshot %s instead of empty failed snapshot %s", snapshot.ID, dataSnapshot.ID, latestFailedSnapshot.ID)
	}
	vulnerabilities, _, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshot.ID, store.VulnerabilityListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListVulnerabilitiesBySnapshot: %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("vulnerability count = %d, want 1", len(vulnerabilities))
	}
}

func TestResolveSnapshotForComponentsViewFallsBackToOlderVulnerabilityDataWhenLatestSnapshotIsEmpty(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	olderDataSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "vuln-data-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(data): %v", err)
	}
	createSnapshotVulnerability(t, srv, olderDataSnapshot.ID, "Known issue", "CVE-2026-1000")
	latestFailedSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "failed-empty-sha", store.SnapshotStatusFailed)
	if err != nil {
		t.Fatalf("CreateSnapshot(failed empty): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepoWithFallback(
		newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug),
		repo,
		"main",
		srv.queries.GetLatestSnapshotWithComponentsByRef,
	)
	if err != nil {
		t.Fatalf("resolveSnapshotForRepoWithFallback: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != olderDataSnapshot.ID {
		t.Fatalf("snapshot id = %s, want older data snapshot %s instead of empty failed snapshot %s", snapshot.ID, olderDataSnapshot.ID, latestFailedSnapshot.ID)
	}
	if snapshot.Status != store.SnapshotStatusPending {
		t.Fatalf("snapshot status = %s, want pending", snapshot.Status)
	}
	if vulnerabilities, _, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshot.ID, store.VulnerabilityListOptions{Limit: 10}); err != nil {
		t.Fatalf("ListVulnerabilitiesBySnapshot: %v", err)
	} else if len(vulnerabilities) != 1 {
		t.Fatalf("vulnerability count = %d, want 1", len(vulnerabilities))
	}
}

func TestResolveSnapshotForDataViewExcludesPurgedSnapshotsFromFallback(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	purgedSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "purged-sha", store.SnapshotStatusPurged)
	if err != nil {
		t.Fatalf("CreateSnapshot(purged): %v", err)
	}
	seedSnapshotComponent(t, srv, purgedSnapshot.ID, "pkg:gomod/github.com/example/purged", "purged-lib", "1.0.0", "go")
	fallbackSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "pending-empty-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(pending): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepoWithFallback(
		newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug),
		repo,
		"main",
		srv.queries.GetLatestSnapshotWithComponentsByRef,
	)
	if err != nil {
		t.Fatalf("resolveSnapshotForRepoWithFallback: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != fallbackSnapshot.ID {
		t.Fatalf("snapshot id = %s, want non-purged fallback snapshot %s instead of purged snapshot %s", snapshot.ID, fallbackSnapshot.ID, purgedSnapshot.ID)
	}
	if snapshot.Status == store.SnapshotStatusPurged {
		t.Fatalf("snapshot status = %s, purged snapshots must not be returned by fallback", snapshot.Status)
	}
}

func TestResolveSnapshotForDataViewDoesNotReturnOnlyPurgedSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	purgedSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "purged-sha", store.SnapshotStatusPurged)
	if err != nil {
		t.Fatalf("CreateSnapshot(purged): %v", err)
	}
	seedSnapshotComponent(t, srv, purgedSnapshot.ID, "pkg:gomod/github.com/example/purged-only", "purged-only-lib", "1.0.0", "go")

	_, snapshot, err := srv.resolveSnapshotForRepoWithFallback(
		newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug),
		repo,
		"main",
		srv.queries.GetLatestSnapshotWithComponentsByRef,
	)
	if err != nil {
		t.Fatalf("resolveSnapshotForRepoWithFallback: %v", err)
	}
	if snapshot != nil {
		t.Fatalf("snapshot = %s, want nil when only purged snapshots remain", snapshot.ID)
	}
}

func TestHandleGetRefComponentsFallsBackToOlderDataBearingSnapshotWhenLatestFailedEmpty(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-components"),
		slug:          uniqueName(t, "analysis-components"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	olderDataSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "component-data-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(data): %v", err)
	}
	seedSnapshotComponent(t, srv, olderDataSnapshot.ID, "pkg:gomod/github.com/example/lib", "example-lib", "1.2.3", "go")
	if _, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "failed-empty-sha", store.SnapshotStatusFailed); err != nil {
		t.Fatalf("CreateSnapshot(failed empty): %v", err)
	}

	recorder := httptest.NewRecorder()
	srv.handleGetRefComponents(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components?ref=main", "github", org.Slug, repo.Slug))

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponents() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response componentListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data) != 1 {
		t.Fatalf("component count = %d, want 1", len(response.Data))
	}
	if response.Data[0].Name != "example-lib" {
		t.Fatalf("component name = %q, want example-lib", response.Data[0].Name)
	}
}

func TestHandleGetRefComponentsIncludesAdvisoryEnrichment(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-components-enriched"),
		slug:          uniqueName(t, "analysis-components-enriched"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "component-enriched-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	componentID, componentVersion := seedSnapshotComponentWithID(t, srv, snapshot.ID, "pkg:gomod/github.com/example/lib", "example-lib", "1.2.3", "go")

	enrichedCanonicalID := "GHSA-" + uuid.NewString()
	kevID := "CVE-2099-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	euvdID := "EUVD-" + kevID[len("CVE-"):]
	enrichedAdvisory, err := upsertRatedAdvisory(context.Background(), srv.queries, dbgen.UpsertAdvisoryParams{
		CanonicalID: enrichedCanonicalID,
		Title:       "Example advisory",
		Description: "Summary from advisory description",
		IsMalware:   false,
	}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelHigh, CvssScore: sql.NullString{String: "8.8", Valid: true}, CvssVector: ""})
	if err != nil {
		t.Fatalf("UpsertAdvisory(enriched): %v", err)
	}
	if err := srv.queries.AddAdvisoryCWEs(context.Background(), enrichedAdvisory.ID, []int{20, 79}); err != nil {
		t.Fatalf("AddAdvisoryCWEs: %v", err)
	}
	if err := srv.queries.UpsertAdvisoryAlias(context.Background(), dbgen.UpsertAdvisoryAliasParams{AdvisoryID: enrichedAdvisory.ID, Alias: kevID}); err != nil {
		t.Fatalf("UpsertAdvisoryAlias: %v", err)
	}
	seedKEVEntries(t, srv, "euvd", []kev.Entry{{CVEID: kevID, VulnerabilityName: euvdID}})
	if _, err := srv.queries.UpsertAdvisorySource(context.Background(), dbgen.UpsertAdvisorySourceParams{
		AdvisoryID: enrichedAdvisory.ID,
		Provider:   "GHSA",
		ProviderID: enrichedCanonicalID,
		RawData:    json.RawMessage(`{"references":[{"url":"https://example.test/advisories/secondary"},{"url":"https://example.test/advisories/primary"},{"url":"not-a-url"}]}`),
		FetchedAt:  snapshot.CreatedAt,
	}); err != nil {
		t.Fatalf("UpsertAdvisorySource(ghsa): %v", err)
	}
	if _, err := srv.queries.UpsertAdvisorySource(context.Background(), dbgen.UpsertAdvisorySourceParams{
		AdvisoryID: enrichedAdvisory.ID,
		Provider:   "NVD",
		ProviderID: kevID,
		RawData:    json.RawMessage(`{"references":[{"url":"https://example.test/advisories/primary"}]}`),
		FetchedAt:  snapshot.CreatedAt,
	}); err != nil {
		t.Fatalf("UpsertAdvisorySource(nvd): %v", err)
	}
	if _, err := srv.queries.CreateAffectedRange(context.Background(), dbgen.CreateAffectedRangeParams{
		AdvisoryID:   enrichedAdvisory.ID,
		Ecosystem:    "go",
		PackageName:  "github.com/example/lib",
		Introduced:   "0",
		Fixed:        "1.2.4",
		LastAffected: "",
		Source:       "ghsa",
	}); err != nil {
		t.Fatalf("CreateAffectedRange(first): %v", err)
	}
	if _, err := srv.queries.CreateAffectedRange(context.Background(), dbgen.CreateAffectedRangeParams{
		AdvisoryID:   enrichedAdvisory.ID,
		Ecosystem:    "go",
		PackageName:  "github.com/example/lib",
		Introduced:   "0",
		Fixed:        "1.3.0",
		LastAffected: "",
		Source:       "nvd",
	}); err != nil {
		t.Fatalf("CreateAffectedRange(second): %v", err)
	}
	if _, err := srv.queries.CreateAffectedRange(context.Background(), dbgen.CreateAffectedRangeParams{
		AdvisoryID:   enrichedAdvisory.ID,
		Ecosystem:    "go",
		PackageName:  "github.com/example/lib",
		Introduced:   "0",
		Fixed:        "1.2.4",
		LastAffected: "",
		Source:       "osv",
	}); err != nil {
		t.Fatalf("CreateAffectedRange(duplicate): %v", err)
	}

	plainAdvisory, err := upsertRatedAdvisory(context.Background(), srv.queries, dbgen.UpsertAdvisoryParams{
		CanonicalID: "HIBOU-2026-0001",
		Title:       "No source advisory",
		Description: "",
		IsMalware:   false,
	}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelMedium, CvssVector: ""})
	if err != nil {
		t.Fatalf("UpsertAdvisory(plain): %v", err)
	}

	createDependencyVulnerabilityForComponent(t, srv, snapshot.ID, componentID, "example-lib", componentVersion, "pkg:gomod/github.com/example/lib", "go", enrichedAdvisory.ID, enrichedAdvisory.CanonicalID, "Example advisory")
	createDependencyVulnerabilityForComponent(t, srv, snapshot.ID, componentID, "example-lib", componentVersion, "pkg:gomod/github.com/example/lib", "go", plainAdvisory.ID, plainAdvisory.CanonicalID, "No source advisory")

	recorder := httptest.NewRecorder()
	srv.handleGetRefComponents(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components?ref=main", "github", org.Slug, repo.Slug))

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponents() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response componentListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Data) != 1 {
		t.Fatalf("component count = %d, want 1", len(response.Data))
	}
	component := response.Data[0]
	if !reflect.DeepEqual(component.Sources, []string{"ghsa", "nvd"}) {
		t.Fatalf("component sources = %v, want %v", component.Sources, []string{"ghsa", "nvd"})
	}
	if component.FixedVersions != nil {
		t.Fatalf("component fixed_versions = %v, want nil when one advisory has no fix", component.FixedVersions)
	}
	if len(component.Advisories) != 2 {
		t.Fatalf("advisory count = %d, want 2", len(component.Advisories))
	}
	advisoriesByID := make(map[uuid.UUID]advisoryResponse, len(component.Advisories))
	for _, advisory := range component.Advisories {
		advisoriesByID[advisory.ID] = advisory
	}
	enriched := advisoriesByID[enrichedAdvisory.ID]
	if enriched.Summary == nil || *enriched.Summary != "Summary from advisory description" {
		t.Fatalf("enriched summary = %v, want advisory description", enriched.Summary)
	}
	// ADR-037: every CWE, each with its catalog title — not just the first id.
	if len(enriched.CWEs) != 2 || enriched.CWEs[0].ID != 20 || enriched.CWEs[1].ID != 79 {
		t.Fatalf("enriched cwes = %+v, want CWE-20 and CWE-79", enriched.CWEs)
	}
	if enriched.CWEs[0].Name != "Improper Input Validation" {
		t.Fatalf("CWE-20 name = %q, want the catalog title", enriched.CWEs[0].Name)
	}
	if enriched.Source == nil || *enriched.Source != "ghsa" {
		t.Fatalf("enriched source = %v, want ghsa", enriched.Source)
	}
	if !reflect.DeepEqual(enriched.FixedVersions, []string{"1.2.4", "1.3.0"}) {
		t.Fatalf("enriched fixed_versions = %v, want %v", enriched.FixedVersions, []string{"1.2.4", "1.3.0"})
	}
	if !reflect.DeepEqual(enriched.References, []string{"https://example.test/advisories/primary", "https://example.test/advisories/secondary"}) {
		t.Fatalf("enriched references = %v, want %v", enriched.References, []string{"https://example.test/advisories/primary", "https://example.test/advisories/secondary"})
	}
	if !reflect.DeepEqual(enriched.Aliases, []string{kevID, euvdID}) {
		t.Fatalf("enriched aliases = %v, want CVE and mirrored EUVD aliases", enriched.Aliases)
	}
	plain := advisoriesByID[plainAdvisory.ID]
	if plain.Source != nil {
		t.Fatalf("plain source = %v, want nil", plain.Source)
	}
	if plain.FixedVersions != nil {
		t.Fatalf("plain fixed_versions = %v, want nil", plain.FixedVersions)
	}
	if plain.References != nil {
		t.Fatalf("plain references = %v, want nil", plain.References)
	}
}

func TestComputeComponentFixedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ecosystem  string
		advisories [][]string
		want       []string
	}{
		{
			name:       "single version fixes all advisories",
			ecosystem:  "go",
			advisories: [][]string{{"1.2.4", "1.3.0"}, {"1.2.4"}},
			want:       []string{"1.2.4"},
		},
		{
			name:       "one advisory unfixed yields empty",
			ecosystem:  "go",
			advisories: [][]string{{"1.2.4"}, nil},
			want:       nil,
		},
		{
			name:       "max of advisory minimum fixes is chosen",
			ecosystem:  "go",
			advisories: [][]string{{"1.2.4"}, {"1.3.0", "1.4.0"}},
			want:       []string{"1.3.0"},
		},
		{
			name:       "no advisories yields empty",
			ecosystem:  "go",
			advisories: nil,
			want:       nil,
		},
		{
			name:       "unsupported ecosystem yields empty",
			ecosystem:  "unknown-ecosystem",
			advisories: [][]string{{"1.2.4"}},
			want:       nil,
		},
		{
			name:       "invalid fixed version yields empty",
			ecosystem:  "go",
			advisories: [][]string{{"not-a-version"}, {"1.3.0"}},
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeComponentFixedVersions(tt.ecosystem, tt.advisories)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("computeComponentFixedVersions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeComponentUsagePaths(t *testing.T) {
	t.Parallel()

	adjacency := map[string][]string{
		"pkg:golang/github.com/example/app":     {"pkg:golang/github.com/example/service", "pkg:golang/github.com/example/worker"},
		"pkg:golang/github.com/example/service": {"pkg:golang/github.com/example/lib"},
		"pkg:golang/github.com/example/worker":  {"pkg:golang/github.com/example/lib"},
	}
	nodeLabels := map[string]string{
		"pkg:golang/github.com/example/app":     "app",
		"pkg:golang/github.com/example/service": "service",
		"pkg:golang/github.com/example/worker":  "worker",
		"pkg:golang/github.com/example/lib":     "lib",
	}

	got := computeComponentUsagePaths("pkg:golang/github.com/example/app", adjacency, nodeLabels, "pkg:golang/github.com/example/lib")
	want := [][]string{{"app", "service", "lib"}, {"app", "worker", "lib"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("computeComponentUsagePaths() = %v, want %v", got, want)
	}

	missing := computeComponentUsagePaths("pkg:golang/github.com/example/app", adjacency, nodeLabels, "pkg:golang/github.com/example/missing")
	if missing != nil {
		t.Fatalf("computeComponentUsagePaths() missing target = %v, want nil", missing)
	}
	noRoot := computeComponentUsagePaths("", adjacency, nodeLabels, "pkg:golang/github.com/example/lib")
	if noRoot != nil {
		t.Fatalf("computeComponentUsagePaths() empty root = %v, want nil", noRoot)
	}
}

func TestShortPurlLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		purl string
		want string
	}{
		{
			name: "namespace and name",
			purl: "pkg:golang/github.com/example/lib@v1.2.3",
			want: "github.com/example/lib",
		},
		{
			name: "query stripped and scope decoded",
			purl: "pkg:npm/%40scope/pkg-name@1.0.0?package-id=123",
			want: "@scope/pkg-name",
		},
		{
			name: "subpath stripped",
			purl: "pkg:golang/github.com/example/lib@v1.2.3#cmd/tool",
			want: "github.com/example/lib",
		},
		{
			name: "name only",
			purl: "pkg:cargo/serde@1.0.0",
			want: "serde",
		},
		{
			name: "empty fallback returns original",
			purl: "pkg:",
			want: "pkg:",
		},
		{
			name: "non-purl returns original",
			purl: "not-a-purl",
			want: "not-a-purl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shortPurlLabel(tt.purl); got != tt.want {
				t.Fatalf("shortPurlLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleGetRefComponentGraphReturnsNodesEdgesAndDeterministicRoot(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "component-graph"),
		slug:          uniqueName(t, "component-graph"),
		provider:      "github",
		providerID:    uniqueName(t, "component-graph-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "graph-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	rootID, rootVersion := seedSnapshotComponentWithID(t, srv, snapshot.ID, "pkg:gomod/github.com/hibouhq/hibou@1.0.0", "hibou", "1.0.0", "go")
	leftID, leftVersion := seedSnapshotComponentWithID(t, srv, snapshot.ID, "pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", "npm")
	rightID, _ := seedSnapshotComponentWithID(t, srv, snapshot.ID, "pkg:npm/chalk@5.0.0", "chalk", "5.0.0", "npm")

	if err := srv.queries.UpsertComponentDependency(context.Background(), snapshot.ID, rootID, leftID); err != nil {
		t.Fatalf("UpsertComponentDependency(root->left): %v", err)
	}
	if err := srv.queries.UpsertComponentDependency(context.Background(), snapshot.ID, rootID, rightID); err != nil {
		t.Fatalf("UpsertComponentDependency(root->right): %v", err)
	}
	if err := srv.queries.UpsertComponentDependency(context.Background(), snapshot.ID, leftID, rightID); err != nil {
		t.Fatalf("UpsertComponentDependency(left->right): %v", err)
	}

	advisory, err := upsertRatedAdvisory(context.Background(), srv.queries, dbgen.UpsertAdvisoryParams{
		CanonicalID: "GHSA-graph-0001",
		Title:       "graph advisory",
		Description: "desc",
	}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelHigh})
	if err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
	createDependencyVulnerabilityForComponent(t, srv, snapshot.ID, rootID, "hibou", rootVersion, "pkg:gomod/github.com/hibouhq/hibou@1.0.0", "go", advisory.ID, "GHSA-graph-0001", "Root vuln")
	createDependencyVulnerabilityForComponent(t, srv, snapshot.ID, rootID, "hibou", rootVersion, "pkg:gomod/github.com/hibouhq/hibou@1.0.0", "go", advisory.ID, "GHSA-graph-0001", "Root vuln duplicate")
	createDependencyVulnerabilityForComponent(t, srv, snapshot.ID, leftID, "left-pad", leftVersion, "pkg:npm/left-pad@1.3.0", "npm", advisory.ID, "GHSA-graph-0001", "Left vuln")

	recorder := httptest.NewRecorder()
	srv.handleGetRefComponentGraph(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components/graph?ref=main", "github", org.Slug, repo.Slug))
	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponentGraph() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response componentGraphEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if response.Data.RootRef != "pkg:gomod/github.com/hibouhq/hibou@1.0.0" {
		t.Fatalf("root_ref = %q, want hibou root", response.Data.RootRef)
	}
	if len(response.Data.Nodes) != 3 {
		t.Fatalf("node count = %d, want 3", len(response.Data.Nodes))
	}
	if response.Data.Nodes[0].Ref != "pkg:gomod/github.com/hibouhq/hibou@1.0.0" {
		t.Fatalf("first node ref = %q, want sorted root purl first", response.Data.Nodes[0].Ref)
	}
	if response.Data.Nodes[0].VulnCount != 1 {
		t.Fatalf("root vuln_count = %d, want 1 after advisory dedupe", response.Data.Nodes[0].VulnCount)
	}
	if response.Data.Nodes[1].VulnCount != 0 {
		t.Fatalf("chalk vuln_count = %d, want 0", response.Data.Nodes[1].VulnCount)
	}
	if response.Data.Nodes[2].VulnCount != 1 {
		t.Fatalf("left-pad vuln_count = %d, want 1", response.Data.Nodes[2].VulnCount)
	}
	if len(response.Data.Edges) != 2 {
		t.Fatalf("edge group count = %d, want 2", len(response.Data.Edges))
	}
	if response.Data.Edges[0].Ref != "pkg:gomod/github.com/hibouhq/hibou@1.0.0" {
		t.Fatalf("first edge ref = %q, want root purl", response.Data.Edges[0].Ref)
	}
	if !reflect.DeepEqual(response.Data.Edges[0].DependsOn, []string{"pkg:npm/chalk@5.0.0", "pkg:npm/left-pad@1.3.0"}) {
		t.Fatalf("root depends_on = %v, want sorted child purls", response.Data.Edges[0].DependsOn)
	}
}

func TestHandleGetRefComponentGraphPrefersPersistedDeclaredRoot(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "component-graph-declared-root"),
		slug:          uniqueName(t, "component-graph-declared-root"),
		provider:      "github",
		providerID:    uniqueName(t, "component-graph-declared-root-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "declared-root-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	writeArtifactForProcessingTest(t, srv, snapshot.ID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"version":1,
		"metadata":{"component":{"bom-ref":"declared-root","name":"declared-root","version":"1.0.0","purl":"pkg:gomod/github.com/example/root@1.0.0"}},
		"components":[
			{"bom-ref":"heuristic-root","name":"heuristic-root","version":"2.0.0","purl":"pkg:npm/heuristic-root@2.0.0"},
			{"bom-ref":"shared-leaf","name":"shared-leaf","version":"3.0.0","purl":"pkg:npm/shared-leaf@3.0.0"}
		],
		"dependencies":[
			{"ref":"heuristic-root","dependsOn":["declared-root","shared-leaf"]}
		]
	}`)
	processArtifactSnapshotForTest(t, srv, snapshot.ID)

	recorder := httptest.NewRecorder()
	srv.handleGetRefComponentGraph(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components/graph?ref=main", "github", org.Slug, repo.Slug))
	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponentGraph() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response componentGraphEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if response.Data.RootRef != "pkg:gomod/github.com/example/root@1.0.0" {
		t.Fatalf("root_ref = %q, want declared root purl", response.Data.RootRef)
	}
	if len(response.Data.Nodes) != 3 || len(response.Data.Edges) != 1 {
		t.Fatalf("graph = %#v, want 3 nodes and 1 edge group", response.Data)
	}
	if response.Data.Edges[0].Ref != "pkg:npm/heuristic-root@2.0.0" {
		t.Fatalf("heuristic edge ref = %q, want heuristic root purl", response.Data.Edges[0].Ref)
	}
}

func TestHandleGetRefComponentGraphGracefullyReturnsEmptyGraph(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "component-graph-empty"),
		slug:          uniqueName(t, "component-graph-empty"),
		provider:      "github",
		providerID:    uniqueName(t, "component-graph-empty-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}

	recorder := httptest.NewRecorder()
	srv.handleGetRefComponentGraph(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components/graph?ref=main", "github", org.Slug, repo.Slug))
	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponentGraph() status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response componentGraphEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if response.Data.RootRef != "" || len(response.Data.Nodes) != 0 || len(response.Data.Edges) != 0 {
		t.Fatalf("empty graph = %#v, want empty root/nodes/edges", response.Data)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "flat-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	seedSnapshotComponent(t, srv, snapshot.ID, "pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0", "npm")

	recorder = httptest.NewRecorder()
	srv.handleGetRefComponentGraph(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components/graph?ref=main", "github", org.Slug, repo.Slug))
	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponentGraph(flat) status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal(flat): %v", err)
	}
	if response.Data.RootRef != "" {
		t.Fatalf("flat root_ref = %q, want empty", response.Data.RootRef)
	}
	if len(response.Data.Nodes) != 1 || len(response.Data.Edges) != 0 {
		t.Fatalf("flat graph = %#v, want one node and zero edges", response.Data)
	}
}

func TestHandleGetRefSummaryUsesResolvedSnapshotStatusWhileEnhancedRefsExposeTrueLatestStatus(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-summary"),
		slug:          uniqueName(t, "analysis-summary"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	olderDataSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "summary-data-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(data): %v", err)
	}
	seedSnapshotComponent(t, srv, olderDataSnapshot.ID, "pkg:gomod/github.com/example/summary", "summary-lib", "2.3.4", "go")
	latestFailedSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "failed-empty-sha", store.SnapshotStatusFailed)
	if err != nil {
		t.Fatalf("CreateSnapshot(failed empty): %v", err)
	}

	summaryRecorder := httptest.NewRecorder()
	srv.handleGetRefSummary(summaryRecorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/summary?ref=main", "github", org.Slug, repo.Slug))
	if summaryRecorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefSummary() status = %d, want %d", summaryRecorder.Code, http.StatusOK)
	}

	var summaryResponse refSummaryEnvelope
	if err := json.NewDecoder(summaryRecorder.Body).Decode(&summaryResponse); err != nil {
		t.Fatalf("decode summary response: %v", err)
	}
	if summaryResponse.Data.ComponentsTotal != 1 {
		t.Fatalf("components_total = %d, want 1", summaryResponse.Data.ComponentsTotal)
	}
	if summaryResponse.Data.SnapshotStatus == nil || *summaryResponse.Data.SnapshotStatus != string(olderDataSnapshot.Status) {
		t.Fatalf("summary snapshot_status = %v, want %q", summaryResponse.Data.SnapshotStatus, olderDataSnapshot.Status)
	}
	if summaryResponse.Data.SnapshotDate == nil || !summaryResponse.Data.SnapshotDate.Equal(olderDataSnapshot.CreatedAt) {
		t.Fatalf("summary snapshot_date = %v, want %v", summaryResponse.Data.SnapshotDate, olderDataSnapshot.CreatedAt)
	}

	refsRecorder := httptest.NewRecorder()
	srv.handleListRefsEnhanced(refsRecorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/refs/enhanced", "github", org.Slug, repo.Slug))
	if refsRecorder.Code != http.StatusOK {
		t.Fatalf("handleListRefsEnhanced() status = %d, want %d", refsRecorder.Code, http.StatusOK)
	}

	var refsResponse enhancedRefsResponse
	if err := json.NewDecoder(refsRecorder.Body).Decode(&refsResponse); err != nil {
		t.Fatalf("decode refs response: %v", err)
	}
	if len(refsResponse.Data) != 1 {
		t.Fatalf("enhanced ref count = %d, want 1", len(refsResponse.Data))
	}
	if refsResponse.Data[0].LatestSnapshotStatus == nil || *refsResponse.Data[0].LatestSnapshotStatus != string(latestFailedSnapshot.Status) {
		t.Fatalf("latest_snapshot_status = %v, want %q", refsResponse.Data[0].LatestSnapshotStatus, latestFailedSnapshot.Status)
	}
	if refsResponse.Data[0].LatestSnapshotID == nil || *refsResponse.Data[0].LatestSnapshotID != latestFailedSnapshot.ID {
		t.Fatalf("latest_snapshot_id = %v, want %s", refsResponse.Data[0].LatestSnapshotID, latestFailedSnapshot.ID)
	}
	if refsResponse.Data[0].LatestSnapshotDate == nil || !refsResponse.Data[0].LatestSnapshotDate.Equal(latestFailedSnapshot.CreatedAt) {
		t.Fatalf("latest_snapshot_date = %v, want %v", refsResponse.Data[0].LatestSnapshotDate, latestFailedSnapshot.CreatedAt)
	}
}

func TestHandleGetRefFindingsFallsBackToOlderDataBearingSnapshotWhenLatestFailedEmpty(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-findings"),
		slug:          uniqueName(t, "analysis-findings"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	olderDataSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "vuln-data-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(data): %v", err)
	}
	createSnapshotVulnerability(t, srv, olderDataSnapshot.ID, "Known issue", "CVE-2026-2000")
	if _, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "failed-empty-sha", store.SnapshotStatusFailed); err != nil {
		t.Fatalf("CreateSnapshot(failed empty): %v", err)
	}

	recorder := httptest.NewRecorder()
	srv.handleGetRefFindings(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/findings?ref=main", "github", org.Slug, repo.Slug))

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefFindings() status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response findingsListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Pagination.Total != 1 {
		t.Fatalf("pagination total = %d, want 1", response.Pagination.Total)
	}
	if len(response.Data) != 1 {
		t.Fatalf("finding count = %d, want 1", len(response.Data))
	}
	if response.Data[0].Title != "Known issue" {
		t.Fatalf("finding title = %q, want Known issue", response.Data[0].Title)
	}
}

func TestDataViewsReturnEmptyResultsAndLatestStatusWhenNoSnapshotHasData(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-empty"),
		slug:          uniqueName(t, "analysis-empty"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	if _, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "older-empty-sha", store.SnapshotStatusPending); err != nil {
		t.Fatalf("CreateSnapshot(older empty): %v", err)
	}
	latestFailedSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "failed-empty-sha", store.SnapshotStatusFailed)
	if err != nil {
		t.Fatalf("CreateSnapshot(failed empty): %v", err)
	}

	componentsRecorder := httptest.NewRecorder()
	srv.handleGetRefComponents(componentsRecorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/components?ref=main", "github", org.Slug, repo.Slug))
	if componentsRecorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefComponents() status = %d, want %d", componentsRecorder.Code, http.StatusOK)
	}
	var componentsResponse componentListResponse
	if err := json.NewDecoder(componentsRecorder.Body).Decode(&componentsResponse); err != nil {
		t.Fatalf("decode components response: %v", err)
	}
	if len(componentsResponse.Data) != 0 {
		t.Fatalf("component count = %d, want 0", len(componentsResponse.Data))
	}

	findingsRecorder := httptest.NewRecorder()
	srv.handleGetRefFindings(findingsRecorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/findings?ref=main", "github", org.Slug, repo.Slug))
	if findingsRecorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefFindings() status = %d, want %d", findingsRecorder.Code, http.StatusOK)
	}
	var findingsResponse findingsListResponse
	if err := json.NewDecoder(findingsRecorder.Body).Decode(&findingsResponse); err != nil {
		t.Fatalf("decode findings response: %v", err)
	}
	if findingsResponse.Pagination.Total != 0 {
		t.Fatalf("findings total = %d, want 0", findingsResponse.Pagination.Total)
	}
	if len(findingsResponse.Data) != 0 {
		t.Fatalf("finding count = %d, want 0", len(findingsResponse.Data))
	}

	summaryRecorder := httptest.NewRecorder()
	srv.handleGetRefSummary(summaryRecorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/summary?ref=main", "github", org.Slug, repo.Slug))
	if summaryRecorder.Code != http.StatusOK {
		t.Fatalf("handleGetRefSummary() status = %d, want %d", summaryRecorder.Code, http.StatusOK)
	}
	var summaryResponse refSummaryEnvelope
	if err := json.NewDecoder(summaryRecorder.Body).Decode(&summaryResponse); err != nil {
		t.Fatalf("decode summary response: %v", err)
	}
	if summaryResponse.Data.SnapshotStatus == nil || *summaryResponse.Data.SnapshotStatus != string(latestFailedSnapshot.Status) {
		t.Fatalf("summary snapshot_status = %v, want %q", summaryResponse.Data.SnapshotStatus, latestFailedSnapshot.Status)
	}
	if summaryResponse.Data.SnapshotDate == nil || !summaryResponse.Data.SnapshotDate.Equal(latestFailedSnapshot.CreatedAt) {
		t.Fatalf("summary snapshot_date = %v, want %v", summaryResponse.Data.SnapshotDate, latestFailedSnapshot.CreatedAt)
	}
	if summaryResponse.Data.ComponentsTotal != 0 {
		t.Fatalf("components_total = %d, want 0", summaryResponse.Data.ComponentsTotal)
	}
	if summaryResponse.Data.Vulnerabilities != (severityCounts{}) {
		t.Fatalf("vulnerability counts = %+v, want zero counts", summaryResponse.Data.Vulnerabilities)
	}
}

func createSnapshotVulnerability(t *testing.T, srv *Server, snapshotID uuid.UUID, title, identifier string) {
	t.Helper()

	if _, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "dependency",
		SnapshotID:             snapshotID,
		Title:                  title,
		Description:            "desc",
		PrimaryIdentifierKind:  "cve",
		PrimaryIdentifierValue: identifier,
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            "unit-test",
		ScannerVendor:          "hibou",
		ScannerVersion:         "1.0",
		ScannerExternalID:      "scanner",
		Fingerprint:            uuid.NewString(),
	}); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}
}

func newRepoRequest(t *testing.T, user *store.User, method, path, provider, slug, repoSlug string) *http.Request {
	t.Helper()

	req := newOrgRequest(t, user, method, path, provider, slug)
	rctx := chi.RouteContext(req.Context())
	rctx.URLParams.Add("repoSlug", repoSlug)
	return req
}

func seedSnapshotComponent(t *testing.T, srv *Server, snapshotID uuid.UUID, purl, name, version, ecosystem string) {
	t.Helper()

	_, _ = seedSnapshotComponentWithID(t, srv, snapshotID, purl, name, version, ecosystem)
}

func seedSnapshotComponentWithID(t *testing.T, srv *Server, snapshotID uuid.UUID, purl, name, version, ecosystem string) (uuid.UUID, string) {
	t.Helper()

	componentID := uuid.New()
	uniqueVersion := fmt.Sprintf("%s-%s", version, componentID.String()[:8])
	if _, err := srv.db.ExecContext(
		context.Background(),
		`INSERT INTO components (id, purl, name, version, ecosystem, licenses) VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[])`,
		componentID,
		purl,
		name,
		uniqueVersion,
		ecosystem,
	); err != nil {
		t.Fatalf("insert component: %v", err)
	}
	if err := srv.queries.AttachComponentToSnapshot(context.Background(), snapshotID, componentID, nil); err != nil {
		t.Fatalf("insert snapshot component: %v", err)
	}

	return componentID, uniqueVersion
}

func createDependencyVulnerabilityForComponent(t *testing.T, srv *Server, snapshotID, componentID uuid.UUID, componentName, componentVersion, componentPurl, ecosystem string, advisoryID uuid.UUID, identifier, title string) {
	t.Helper()

	if _, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "dependency",
		SnapshotID:             snapshotID,
		Title:                  title,
		Description:            "desc",
		PrimaryIdentifierKind:  "advisory",
		PrimaryIdentifierValue: identifier,
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            "unit-test",
		ScannerVendor:          "hibou",
		ScannerVersion:         "1.0",
		ScannerExternalID:      "scanner",
		Fingerprint:            uuid.NewString(),
		ComponentID:            uuid.NullUUID{UUID: componentID, Valid: true},
		ComponentName:          sql.NullString{String: componentName, Valid: componentName != ""},
		ComponentVersion:       sql.NullString{String: componentVersion, Valid: componentVersion != ""},
		ComponentPurl:          sql.NullString{String: componentPurl, Valid: componentPurl != ""},
		Ecosystem:              sql.NullString{String: ecosystem, Valid: ecosystem != ""},
		AdvisoryID:             uuid.NullUUID{UUID: advisoryID, Valid: true},
		Metadata:               json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}
}
