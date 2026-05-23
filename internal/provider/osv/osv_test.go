package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/advisory"
	"github.com/hibouhq/lehibou/internal/provider"
)

func TestQueryPackagesBasicMapping(t *testing.T) {
	var gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("expected /v1/querybatch, got %s", r.URL.Path)
		}

		var req queryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Queries) != 1 {
			t.Fatalf("expected 1 query, got %d", len(req.Queries))
		}
		if req.Queries[0].Package.Ecosystem != "npm" {
			t.Fatalf("expected npm ecosystem, got %s", req.Queries[0].Package.Ecosystem)
		}
		if req.Queries[0].Version != "" {
			t.Fatalf("expected version to be omitted from query, got %q", req.Queries[0].Version)
		}

		_ = json.NewEncoder(w).Encode(queryBatchResponse{
			Results: []queryResult{{
				Vulns: []vulnerability{{
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
				}},
			}},
		})
	}))
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
	if gotUserAgent != "hibou/dev" {
		t.Fatalf("expected user agent hibou/dev, got %s", gotUserAgent)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.ProviderName != "osv" {
		t.Fatalf("expected provider osv, got %s", result.ProviderName)
	}
	if result.ProviderID != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("expected provider id to be mapped")
	}
	if !reflect.DeepEqual(result.Aliases, []string{"CVE-2021-12345"}) {
		t.Fatalf("aliases mismatch: %#v", result.Aliases)
	}
	if result.CVSSVersion == nil || *result.CVSSVersion != advisory.CVSSVersionV31 {
		t.Fatalf("expected CVSS v3.1, got %#v", result.CVSSVersion)
	}
	if result.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("expected CVSS vector to be preserved, got %s", result.CVSSVector)
	}
	if result.Severity == nil || *result.Severity != advisory.SeverityHigh {
		t.Fatalf("expected high severity, got %#v", result.Severity)
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

func TestQueryPackagesOmitsVersionAndExpandsRPM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string][]map[string]any
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		queries := reqBody["queries"]
		if len(queries) != 4 {
			t.Fatalf("expected 4 expanded rpm queries, got %d", len(queries))
		}

		gotEcosystems := make([]string, 0, len(queries))
		for _, query := range queries {
			if _, ok := query["version"]; ok {
				t.Fatal("expected version field to be omitted from OSV query")
			}
			pkg, ok := query["package"].(map[string]any)
			if !ok {
				t.Fatalf("expected package object, got %#v", query["package"])
			}
			ecosystem, _ := pkg["ecosystem"].(string)
			gotEcosystems = append(gotEcosystems, ecosystem)
		}

		expected := []string{"Red Hat", "Rocky Linux", "AlmaLinux", "SUSE"}
		if !reflect.DeepEqual(gotEcosystems, expected) {
			t.Fatalf("unexpected rpm ecosystem expansion: %#v", gotEcosystems)
		}

		_ = json.NewEncoder(w).Encode(queryBatchResponse{
			Results: []queryResult{
				{Vulns: []vulnerability{{
					ID:      "RHSA-1",
					Summary: "rhel advisory",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "openssl", Ecosystem: "Red Hat"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.0.2"}}}},
					}},
				}}},
				{Vulns: []vulnerability{{
					ID:      "ROCKY-1",
					Summary: "rocky advisory",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "openssl", Ecosystem: "Rocky Linux"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.0.3"}}}},
					}},
				}}},
				{},
				{},
			},
		})
	}))
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "rpm",
		Name:      "openssl",
		Version:   "1.0.1",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 rpm results, got %d", len(results))
	}
	if results[0].AffectedRanges[0].Ecosystem != "rpm" || results[1].AffectedRanges[0].Ecosystem != "rpm" {
		t.Fatalf("expected rpm normalization, got %#v", results)
	}
}

func TestQueryPackagesDedupesRPMAdvisoriesByProviderID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{
			Results: []queryResult{
				{Vulns: []vulnerability{{
					ID:      "CVE-2024-1234",
					Aliases: []string{"GHSA-dup-1"},
					Summary: "red hat advisory",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "openssl", Ecosystem: "Red Hat"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.0.2"}}}},
					}},
				}}},
				{Vulns: []vulnerability{{
					ID:      "CVE-2024-1234",
					Aliases: []string{"GHSA-dup-1"},
					Summary: "rocky advisory",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "openssl", Ecosystem: "Rocky Linux"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.0.2"}}}},
					}},
				}}},
				{},
				{},
			},
		})
	}))
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{
		Ecosystem: "rpm",
		Name:      "openssl",
		Version:   "1.0.1",
	}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 deduped rpm result, got %d", len(results))
	}
	if results[0].ProviderID != "CVE-2024-1234" {
		t.Fatalf("unexpected provider id: %s", results[0].ProviderID)
	}
	if results[0].AffectedRanges[0].Ecosystem != "rpm" {
		t.Fatalf("expected rpm normalization, got %#v", results[0].AffectedRanges)
	}
}

func TestQueryPackagesMultiplePackages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{
			Results: []queryResult{
				{Vulns: []vulnerability{{
					ID:      "GHSA-one",
					Summary: "one",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "lodash", Ecosystem: "npm"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "4.17.21"}}}},
					}},
				}}},
				{Vulns: []vulnerability{{
					ID:      "GHSA-two",
					Summary: "two",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "django", Ecosystem: "PyPI"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}, {Fixed: "3.2.2"}}}},
					}},
				}}},
			},
		})
	}))
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{Results: []queryResult{{}}})
	}))
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{
			Results: []queryResult{{
				Vulns: []vulnerability{{
					ID:      "MAL-2024-0001",
					Summary: "bad package",
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "pkg", Ecosystem: "npm"},
						Ranges:  []affectedRange{{Type: "ECOSYSTEM", Events: []rangeEvent{{Introduced: "0"}}}},
					}},
				}},
			}},
		})
	}))
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(queryBatchResponse{
			Results: []queryResult{{
				Vulns: []vulnerability{{
					ID:      "GHSA-ranges",
					Summary: "ranges",
					Severity: []severityEntry{{
						Type:  "CVSS_V2",
						Score: "5.0",
					}},
					Affected: []affectedPackage{{
						Package: queryPackage{Name: "pkg", Ecosystem: "Debian"},
						Ranges: []affectedRange{{
							Type:   "ECOSYSTEM",
							Events: []rangeEvent{{Introduced: "0"}, {Fixed: "1.2.0"}, {Introduced: "1.3.0"}, {LastAffected: "1.3.5"}},
						}},
					}},
				}},
			}},
		})
	}))
	defer server.Close()

	prov := New(server.URL, zerolog.Nop())
	results, err := prov.QueryPackages(context.Background(), []provider.PackageQuery{{Ecosystem: "deb", Name: "pkg"}})
	if err != nil {
		t.Fatalf("QueryPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	result := results[0]
	if result.CVSSScore == nil || *result.CVSSScore != 5.0 {
		t.Fatalf("expected CVSS score 5.0, got %#v", result.CVSSScore)
	}
	if result.CVSSVersion == nil || *result.CVSSVersion != advisory.CVSSVersionV2 {
		t.Fatalf("expected CVSS v2, got %#v", result.CVSSVersion)
	}
	if len(result.AffectedRanges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(result.AffectedRanges))
	}
	if result.AffectedRanges[0].Ecosystem != "deb" || result.AffectedRanges[1].LastAffected != "1.3.5" {
		t.Fatalf("unexpected ranges: %#v", result.AffectedRanges)
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
