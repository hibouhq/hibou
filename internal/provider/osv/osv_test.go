package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/provider"
)

func osvTestServer(
	t *testing.T,
	resultsByQuery [][]string,
	vulnsByID map[string]vulnerability,
	assertQuery func(*testing.T, queryBatchRequest, *http.Request),
	onHydrate func(string),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			handleOSVQueryBatch(t, w, r, resultsByQuery, assertQuery)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			handleOSVVulnFetch(w, r, vulnsByID, onHydrate)
			return
		}
		t.Fatalf("unexpected path %s", r.URL.Path)
	}))
}

func handleOSVQueryBatch(
	t *testing.T,
	w http.ResponseWriter,
	r *http.Request,
	resultsByQuery [][]string,
	assertQuery func(*testing.T, queryBatchRequest, *http.Request),
) {
	t.Helper()
	var req queryBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if assertQuery != nil {
		assertQuery(t, req, r)
	}
	if len(req.Queries) != len(resultsByQuery) {
		t.Fatalf("expected %d query results, got %d requests", len(resultsByQuery), len(req.Queries))
	}
	_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: batchResultsForIDs(resultsByQuery)})
}

func handleOSVVulnFetch(w http.ResponseWriter, r *http.Request, vulnsByID map[string]vulnerability, onHydrate func(string)) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
	if onHydrate != nil {
		onHydrate(id)
	}
	vuln, ok := vulnsByID[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(vuln)
}

func batchResultsForIDs(resultsByQuery [][]string) []queryResult {
	results := make([]queryResult, len(resultsByQuery))
	for i, ids := range resultsByQuery {
		results[i] = queryResult{Vulns: vulnerabilitiesForIDs(ids)}
	}
	return results
}

func vulnerabilitiesForIDs(ids []string) []vulnerability {
	vulns := make([]vulnerability, 0, len(ids))
	for _, id := range ids {
		vulns = append(vulns, vulnerability{ID: id})
	}
	return vulns
}

func basicMappingVulnerability() vulnerability {
	return vulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Aliases: []string{"CVE-2021-12345"},
		Summary: "lodash issue",
		Details: "details",
		Severity: []severityEntry{
			{Type: "CVSS_V2", Score: "4.3"},
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []affectedPackage{{
			Package: queryPackage{Name: "lodash", Ecosystem: "npm"},
			Ranges: []affectedRange{{
				Type:   "ECOSYSTEM",
				Events: []rangeEvent{{Introduced: "0"}, {Fixed: "4.17.21"}},
			}},
		}},
		Published: "2021-05-06T00:00:00Z",
		Withdrawn: "2024-01-01T00:00:00Z",
		DatabaseSpecific: vulnerabilityDBSpecific{
			Severity: "high",
			CWEIDs:   []string{"CWE-79", "CWE-89"},
		},
	}
}

func assertBasicMappingQuery(t *testing.T, req queryBatchRequest, r *http.Request, gotUserAgent *string) {
	t.Helper()
	*gotUserAgent = r.Header.Get("User-Agent")
	if len(req.Queries) != 1 {
		t.Fatalf("expected 1 query, got %d", len(req.Queries))
	}
	if req.Queries[0].Package.Ecosystem != "npm" {
		t.Fatalf("expected npm ecosystem, got %s", req.Queries[0].Package.Ecosystem)
	}
	if req.Queries[0].Version != "" {
		t.Fatalf("expected version to be omitted from query, got %q", req.Queries[0].Version)
	}
}

func assertBasicMappingResult(t *testing.T, results []provider.AdvisoryResult, gotUserAgent string) {
	t.Helper()
	if gotUserAgent != "hibou/dev" {
		t.Fatalf("expected user agent hibou/dev, got %s", gotUserAgent)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	assertBasicMappingAdvisory(t, results[0])
}

func assertBasicMappingAdvisory(t *testing.T, result provider.AdvisoryResult) {
	t.Helper()
	if result.ProviderName != "osv" {
		t.Fatalf("expected provider osv, got %s", result.ProviderName)
	}
	if result.ProviderID != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("expected provider id to be mapped")
	}
	if !reflect.DeepEqual(result.Aliases, []string{"CVE-2021-12345"}) {
		t.Fatalf("aliases mismatch: %#v", result.Aliases)
	}
	// Every statement is kept (ADR-038 §2): the v2 number, the v3.1 vector
	// scored by hibou, and GitHub's own label.
	v31 := findRating(t, result.Ratings, "ghsa", advisory.CVSSVersionV31)
	if v31.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" || v31.Score == nil || *v31.Score != 9.8 {
		t.Fatalf("v3.1 rating: %+v", v31)
	}
	if v2 := findRating(t, result.Ratings, "ghsa", advisory.CVSSVersionV2); *v2.Score != 4.3 {
		t.Fatalf("v2 rating: %+v", v2)
	}
	if choice := advisory.Headline(result.Ratings); choice.Severity != advisory.SeverityHigh {
		t.Fatalf("GitHub's label wins over the band of its score: %+v", choice)
	}
	if !reflect.DeepEqual(result.CWEIDs, []string{"CWE-79", "CWE-89"}) {
		t.Fatalf("cwe mismatch: %#v", result.CWEIDs)
	}
	if len(result.AffectedRanges) != 1 {
		t.Fatalf("expected 1 affected range, got %d", len(result.AffectedRanges))
	}
	if result.AffectedRanges[0].PackageName != "lodash" || result.AffectedRanges[0].Fixed != "4.17.21" {
		t.Fatalf("affected range was not mapped correctly: %#v", result.AffectedRanges[0])
	}
	if result.PublishedAt == nil || result.WithdrawnAt == nil {
		t.Fatalf("expected timestamps to be parsed")
	}
	if len(result.RawData) == 0 {
		t.Fatal("expected raw data to be populated")
	}
}

func TestQueryPackagesBasicMapping(t *testing.T) {
	var gotUserAgent string
	server := osvTestServer(
		t,
		[][]string{{"GHSA-xxxx-yyyy-zzzz"}},
		map[string]vulnerability{
			"GHSA-xxxx-yyyy-zzzz": basicMappingVulnerability(),
		},
		func(t *testing.T, req queryBatchRequest, r *http.Request) {
			assertBasicMappingQuery(t, req, r, &gotUserAgent)
		},
		nil,
	)
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.20",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	assertBasicMappingResult(t, results, gotUserAgent)
}

func TestQueryPackagesSkipsRPMAndUnreleasedDistroQueries(t *testing.T) {
	// rpm never queries OSV (Red Hat stream qualifiers cannot be release-
	// matched), and apk/deb without a distro qualifier fail closed. No HTTP
	// request may be issued for any of these.
	prov := New("http://127.0.0.1:1", zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "rpm", Name: "openssl", Version: "1.0.1", Distro: "redhat-9.4"},
		{Ecosystem: "apk", Name: "busybox", Version: "1.36.1-r5"},
		{Ecosystem: "deb", Name: "libssl3", Version: "3.0.11"},
	})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %d", len(results))
	}
}

func TestQueryPackagesReleaseQualifiedDistro(t *testing.T) {
	server := osvTestServer(
		t,
		[][]string{{"CVE-2024-1"}},
		map[string]vulnerability{
			"CVE-2024-1": {
				ID:      "CVE-2024-1",
				Summary: "alpine advisory",
				Affected: []affectedPackage{
					{
						Package: queryPackage{Name: "busybox", Ecosystem: "Alpine:v3.18"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.36.1-r6"}}}},
					},
					{
						// Same record, other release: must be scoped to 3.19, and the
						// open-ended entry (no fixed yet) must be dropped entirely.
						Package: queryPackage{Name: "busybox", Ecosystem: "Alpine:v3.19"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}}}},
					},
				},
			},
		},
		func(t *testing.T, req queryBatchRequest, _ *http.Request) {
			if len(req.Queries) != 1 {
				t.Fatalf("expected 1 query, got %d", len(req.Queries))
			}
			if req.Queries[0].Package.Ecosystem != "Alpine:v3.18" {
				t.Fatalf("expected release-qualified ecosystem, got %q", req.Queries[0].Package.Ecosystem)
			}
		},
		nil,
	)
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "apk",
		Name:      "busybox",
		Version:   "1.36.1-r5",
		Distro:    "alpine-3.18.4",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	ranges := results[0].AffectedRanges
	if len(ranges) != 1 {
		t.Fatalf("expected the open-ended 3.19 range to be dropped, got %#v", ranges)
	}
	if ranges[0].Ecosystem != "apk" || ranges[0].Release != "3.18" || ranges[0].Fixed != "1.36.1-r6" {
		t.Fatalf("unexpected range: %#v", ranges[0])
	}
}

func TestQueryPackagesMultiplePackages(t *testing.T) {
	server := osvTestServer(
		t,
		[][]string{{"GHSA-one"}, {"GHSA-two"}},
		map[string]vulnerability{
			"GHSA-one": {
				ID:      "GHSA-one",
				Summary: "one",
				Affected: []affectedPackage{{
					Package: queryPackage{Name: "lodash", Ecosystem: "npm"},
					Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "4.17.21"}}}},
				}},
			},
			"GHSA-two": {
				ID:      "GHSA-two",
				Summary: "two",
				Affected: []affectedPackage{{
					Package: queryPackage{Name: "django", Ecosystem: "PyPI"},
					Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "3.2.2"}}}},
				}},
			},
		},
		nil,
		nil,
	)
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.20",
	}, {
		Ecosystem: "pypi",
		Name:      "django",
		Version:   "3.2.1",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	gotIDs := []string{results[0].ProviderID, results[1].ProviderID}
	if !reflect.DeepEqual(gotIDs, []string{"GHSA-one", "GHSA-two"}) {
		t.Fatalf("unexpected result ordering: %#v", gotIDs)
	}
	if results[1].AffectedRanges[0].Ecosystem != "pypi" {
		t.Fatalf("expected pypi ecosystem, got %s", results[1].AffectedRanges[0].Ecosystem)
	}
}

func TestQueryPackagesEmptyResults(t *testing.T) {
	server := osvTestServer(t, [][]string{{}}, map[string]vulnerability{}, nil, nil)
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{Ecosystem: "npm", Name: "lodash"}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %d", len(results))
	}
}

func TestQueryPackagesMalwareDetection(t *testing.T) {
	server := osvTestServer(
		t,
		[][]string{{"MAL-2024-0001"}},
		map[string]vulnerability{
			"MAL-2024-0001": {
				ID:      "MAL-2024-0001",
				Summary: "bad package",
				Affected: []affectedPackage{{
					Package: queryPackage{Name: "pkg", Ecosystem: "npm"},
					Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
		},
		nil,
		nil,
	)
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{Ecosystem: "npm", Name: "pkg"}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 1 || !results[0].IsMalware {
		t.Fatalf("expected malware result, got %#v", results)
	}
}

func TestQueryPackagesCVSSFallbackAndRanges(t *testing.T) {
	server := osvTestServer(
		t,
		[][]string{{"GHSA-ranges"}},
		map[string]vulnerability{
			"GHSA-ranges": {
				ID:      "GHSA-ranges",
				Summary: "ranges",
				Severity: []severityEntry{{
					Type:  "CVSS_V2",
					Score: "5.0",
				}},
				Affected: []affectedPackage{{
					Package: queryPackage{Name: "pkg", Ecosystem: "Debian:12"},
					Ranges: []affectedRange{{
						Type:   "ECOSYSTEM",
						Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.2.0"}, {Introduced: "1.3.0"}, {LastAffected: "1.3.5"}},
					}},
				}},
			},
		},
		nil,
		nil,
	)
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{Ecosystem: "deb", Name: "pkg", Distro: "debian-12"}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	result := results[0]
	if v2 := findRating(t, result.Ratings, "ghsa", advisory.CVSSVersionV2); v2.Score == nil || *v2.Score != 5.0 {
		t.Fatalf("expected CVSS v2 score 5.0, got %+v", v2)
	}
	if len(result.AffectedRanges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(result.AffectedRanges))
	}
	if result.AffectedRanges[0].Ecosystem != "deb" || result.AffectedRanges[1].LastAffected != "1.3.5" {
		t.Fatalf("unexpected ranges: %#v", result.AffectedRanges)
	}
}

func TestQueryPackagesHydratesVulnDetails(t *testing.T) {
	var hydrateCalls atomic.Int32
	server := osvTestServer(
		t,
		[][]string{{"GHSA-hydrated"}},
		map[string]vulnerability{
			"GHSA-hydrated": {
				ID:       "GHSA-hydrated",
				Summary:  "hydrated",
				Severity: []severityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: []affectedPackage{{
					Package: queryPackage{Name: "pkg", Ecosystem: "npm"},
					Ranges: []affectedRange{{
						Type:   "ECOSYSTEM",
						Events: []rangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}},
					}},
				}},
				DatabaseSpecific: vulnerabilityDBSpecific{Severity: "critical"},
			},
		},
		nil,
		func(id string) {
			if id == "GHSA-hydrated" {
				hydrateCalls.Add(1)
			}
		},
	)
	defer server.Close()

	results, err := New(server.URL, zerolog.Nop()).QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "npm",
		Name:      "pkg",
		Version:   "1.0.0",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if hydrateCalls.Load() != 1 {
		t.Fatalf("expected 1 hydration request, got %d", hydrateCalls.Load())
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].AffectedRanges) != 1 || results[0].AffectedRanges[0].Fixed != "2.0.0" {
		t.Fatalf("expected hydrated affected range, got %#v", results[0].AffectedRanges)
	}
	if choice := advisory.Headline(results[0].Ratings); choice.Severity != advisory.SeverityCritical {
		t.Fatalf("expected hydrated severity, got %+v", choice)
	}
}

func TestFetchVulnNotFoundSkipped(t *testing.T) {
	server := osvTestServer(
		t,
		[][]string{{"GHSA-missing", "GHSA-present"}},
		map[string]vulnerability{
			"GHSA-present": {
				ID:      "GHSA-present",
				Summary: "present",
				Affected: []affectedPackage{{
					Package: queryPackage{Name: "pkg", Ecosystem: "npm"},
					Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.0.1"}}}},
				}},
			},
		},
		nil,
		nil,
	)
	defer server.Close()

	results, err := New(server.URL, zerolog.Nop()).QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "npm",
		Name:      "pkg",
		Version:   "1.0.0",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 hydrated result, got %d", len(results))
	}
	if results[0].ProviderID != "GHSA-present" {
		t.Fatalf("unexpected provider id: %s", results[0].ProviderID)
	}
}

func TestQueryPackagesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	_, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{Ecosystem: "npm", Name: "pkg"}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryPackagesInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":`))
	}))
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	_, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{Ecosystem: "npm", Name: "pkg"}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMapAffectedPackageRangesAcceptsSemver(t *testing.T) {
	// GHSA publishes SEMVER ranges for npm/Go/cargo; only accepting ECOSYSTEM
	// dropped nearly every advisory in those ecosystems.
	pkg := affectedPackage{
		Package: queryPackage{Name: "lodash", Ecosystem: "npm"},
		Ranges: []affectedRange{
			{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "4.17.21"}}},
			{Type: "GIT", Events: []rangeEvent{{Introduced: "abc123"}}},
		},
	}
	ranges := mapAffectedPackageRanges(pkg)
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range (SEMVER kept, GIT dropped), got %d", len(ranges))
	}
	if ranges[0].Fixed != "4.17.21" || ranges[0].Ecosystem != "npm" {
		t.Fatalf("unexpected range: %+v", ranges[0])
	}
}

func findRating(t *testing.T, ratings []advisory.Rating, rater string, version advisory.CVSSVersion) advisory.Rating {
	t.Helper()
	for _, rating := range ratings {
		if rating.Rater == rater && rating.Version != nil && *rating.Version == version {
			return rating
		}
	}
	t.Fatalf("no %s %s rating in %+v", rater, version, ratings)
	return advisory.Rating{}
}

// The live Log4Shell record (GHSA-jfh8-c2jp-5v3q) ships a v3.1 vector with a
// temporal metric and no number: it used to be stored unscored (ADR-038,
// defect 1).
func TestRatingsScoreOSVVectors(t *testing.T) {
	ratings := ratingsFor(vulnerability{
		ID:               "GHSA-jfh8-c2jp-5v3q",
		Severity:         []severityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"}},
		DatabaseSpecific: vulnerabilityDBSpecific{Severity: "CRITICAL"},
	})
	v31 := findRating(t, ratings, "ghsa", advisory.CVSSVersionV31)
	if v31.Score == nil || *v31.Score != 10.0 {
		t.Fatalf("Log4Shell scores 10.0: %+v", v31)
	}
	if raterFor("PYSEC-2021-1") != "pypa" || raterFor("GO-2022-0535") != "go" || raterFor("CVE-2020-0601") != "nvd" {
		t.Fatal("raters from id prefixes")
	}
}
