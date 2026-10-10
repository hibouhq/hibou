package trivy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/provider"
)

func newTestProvider(t *testing.T, handler http.HandlerFunc) *Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(srv.URL, zerolog.Nop())
}

func TestQueryPackagesMapsVulnerabilities(t *testing.T) {
	var putArtifactCalled, putBlobCalled, scanCalled bool
	var capturedBlob putBlobRequest

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "PutArtifact"):
			putArtifactCalled = true
			writeJSON(t, w, map[string]any{})
		case strings.HasSuffix(r.URL.Path, "PutBlob"):
			putBlobCalled = true
			if err := json.Unmarshal(body, &capturedBlob); err != nil {
				t.Errorf("decode blob request: %v", err)
			}
			writeJSON(t, w, map[string]any{})
		case strings.HasSuffix(r.URL.Path, "Scan"):
			scanCalled = true
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Target: "package-lock.json",
				Type:   "npm",
				Class:  "lang-pkgs",
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2020-28500",
					PkgName:          "lodash",
					InstalledVersion: "4.17.15",
					FixedVersion:     "4.17.21",
					Title:            "lodash ReDoS",
					Description:      "Regular expression denial of service",
					Severity:         "MEDIUM",
					CweIDs:           []string{"CWE-400"},
					CVSS: map[string]trivyCVSS{
						"nvd": {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", V3Score: 5.3},
					},
					PublishedDate: "2021-02-15T11:15:00Z",
				}},
			}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}

	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if !putArtifactCalled || !putBlobCalled || !scanCalled {
		t.Fatalf("expected all twirp endpoints called: artifact=%v blob=%v scan=%v", putArtifactCalled, putBlobCalled, scanCalled)
	}
	if capturedBlob.BlobInfo.SchemaVersion != blobSchemaVersion {
		t.Errorf("expected blob schema version %d, got %d", blobSchemaVersion, capturedBlob.BlobInfo.SchemaVersion)
	}
	if len(capturedBlob.BlobInfo.Applications) != 1 || capturedBlob.BlobInfo.Applications[0].Type != "npm" {
		t.Fatalf("expected single npm application, got %+v", capturedBlob.BlobInfo.Applications)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 advisory result, got %d", len(results))
	}
	got := results[0]
	if got.ProviderName != "trivy" || got.ProviderID != "CVE-2020-28500" {
		t.Errorf("unexpected provider identity: %+v", got)
	}
	if len(got.AffectedRanges) != 1 {
		t.Fatalf("expected 1 affected range, got %d", len(got.AffectedRanges))
	}
	rng := got.AffectedRanges[0]
	if rng.Ecosystem != "npm" || rng.PackageName != "lodash" || rng.Fixed != "4.17.21" || rng.Introduced != "0" || rng.Source != "trivy" {
		t.Errorf("unexpected affected range: %+v", rng)
	}
	choice := advisory.Headline(got.Ratings)
	if choice.RatedBy() != "nvd" || *choice.Rating.Score != 5.3 || *choice.Rating.Version != advisory.CVSSVersionV31 || choice.Severity != advisory.SeverityMedium {
		t.Errorf("expected nvd v3.1 5.3 medium, got %+v", choice)
	}
}

// What the Trivy server returned for CVE-2024-13176 on RHEL 9.2: every
// vendor's rating is kept, and Red Hat's label rides on its CVSS rating.
func TestRatingsKeepEveryVendor(t *testing.T) {
	ratings := ratingsFor(trivyVulnerability{
		VulnerabilityID: "CVE-2024-13176",
		Severity:        "LOW",
		SeveritySource:  "redhat",
		VendorSeverity:  map[string]string{"alma": "MEDIUM", "oracle-oval": "MEDIUM", "redhat": "LOW", "ubuntu": "LOW"},
		CVSS: map[string]trivyCVSS{
			"julia":  {V3Vector: "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", V3Score: 4.1},
			"redhat": {V3Vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", V3Score: 4.7},
		},
	})
	byRater := map[string]advisory.Rating{}
	for _, rating := range ratings {
		byRater[rating.Rater] = rating
	}
	if len(byRater) != 5 {
		t.Fatalf("raters: %v", byRater)
	}
	redhat := byRater["redhat"]
	if *redhat.Score != 4.7 || redhat.Label == nil || *redhat.Label != advisory.SeverityLow {
		t.Fatalf("redhat: %+v", redhat)
	}
	if oracle := byRater["oracle"]; oracle.Label == nil || *oracle.Label != advisory.SeverityMedium || oracle.Vector != "" {
		t.Fatalf("oracle-oval folds to oracle, label only: %+v", oracle)
	}
	choice := advisory.ForFinding(ratings, "rpm", "pkg:rpm/redhat/openssl@3.0.7-6.el9_2?distro=redhat-9.2")
	if choice.RatedBy() != "redhat" || choice.Severity != advisory.SeverityLow {
		t.Fatalf("RHEL finding uses Red Hat's rating: %+v", choice)
	}
}

func TestQueryPackagesSkipsUnknownEcosystems(t *testing.T) {
	called := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "haskell", Name: "aeson", Version: "1.0"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if called {
		t.Fatal("expected no twirp calls when all ecosystems unsupported")
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %d", len(results))
	}
}

func TestQueryPackagesNoFixedVersionUsesLastAffected(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Type: "pip",
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2019-0000",
					PkgName:          "requests",
					InstalledVersion: "2.20.0",
					Severity:         "HIGH",
				}},
			}}})
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "pypi", Name: "requests", Version: "2.20.0"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rng := results[0].AffectedRanges[0]
	if rng.Ecosystem != "pypi" || rng.Fixed != "" || rng.LastAffected != "2.20.0" {
		t.Errorf("unexpected range without fix: %+v", rng)
	}
}

func TestQueryPackagesPropagatesScanError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"internal","msg":"boom"}`))
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	_, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"},
	})
	if err == nil {
		t.Fatal("expected error from failing scan")
	}
}

func TestQueryPackagesMultiFixedVersionPicksBranchAboveInstalled(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Type: "npm",
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2024-0001",
					PkgName:          "example",
					InstalledVersion: "2.0.0",
					FixedVersion:     "1.2.5, 2.0.1, 3.0.0",
					Severity:         "HIGH",
				}},
			}}})
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "npm", Name: "example", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rng := results[0].AffectedRanges[0]
	// 2.0.1 is the smallest fix strictly greater than the installed 2.0.0, so
	// [0, 2.0.1) keeps the installed version inside the affected range.
	if rng.Fixed != "2.0.1" {
		t.Errorf("expected fixed 2.0.1 for installed 2.0.0, got %q", rng.Fixed)
	}
}

func TestQueryPackagesUsesOriginalQueryNameNotTrivyCasing(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Type: "python-pkg", // alias of the uploaded "pip" type
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2024-0002",
					PkgName:          "Flask", // Trivy may echo different casing
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.1.0",
					Severity:         "LOW",
				}},
			}}})
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "pypi", Name: "flask", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rng := results[0].AffectedRanges[0]
	if rng.PackageName != "flask" {
		t.Errorf("expected original query name 'flask', got %q", rng.PackageName)
	}
	if rng.Ecosystem != "pypi" {
		t.Errorf("expected ecosystem pypi, got %q", rng.Ecosystem)
	}
}

func TestQueryPackagesFallsBackToResultTypeEcosystem(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Type: "npm",
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2024-0003",
					PkgName:          "transitive-dep", // not in our query set
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Severity:         "MEDIUM",
				}},
			}}})
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rng := results[0].AffectedRanges[0]
	if rng.Ecosystem != "npm" || rng.PackageName != "transitive-dep" {
		t.Errorf("expected fallback ecosystem npm + Trivy name, got %+v", rng)
	}
}

func TestQueryPackagesNoFixAboveInstalledUsesLastAffected(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Type: "npm",
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2024-0004",
					PkgName:          "example",
					InstalledVersion: "3.0.0",
					FixedVersion:     "1.2.5, 2.0.1", // all fixes below installed
					Severity:         "HIGH",
				}},
			}}})
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "npm", Name: "example", Version: "3.0.0"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rng := results[0].AffectedRanges[0]
	// No fix is strictly greater than 3.0.0, so bound by the installed version.
	if rng.Fixed != "" || rng.LastAffected != "3.0.0" {
		t.Errorf("expected LastAffected=3.0.0 with empty Fixed, got %+v", rng)
	}
}

func TestQueryPackagesUnregisteredComparatorUsesFirstFix(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Scan") {
			writeJSON(t, w, scanResponse{Results: []scanResult{{
				Type: "composer",
				Vulnerabilities: []trivyVulnerability{{
					VulnerabilityID:  "CVE-2024-0005",
					PkgName:          "vendor/pkg",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1, 1.2.0",
					Severity:         "MEDIUM",
				}},
			}}})
			return
		}
		writeJSON(t, w, map[string]any{})
	}
	p := newTestProvider(t, handler)
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "packagist", Name: "vendor/pkg", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("QueryPackages: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	rng := results[0].AffectedRanges[0]
	// packagist has no versioncmp comparator, so the first listed fix is used.
	if rng.Ecosystem != "packagist" || rng.PackageName != "vendor/pkg" || rng.Fixed != "1.0.1" {
		t.Errorf("unexpected range for unregistered comparator: %+v", rng)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestBuildOSGroupsAndPkgSplitting(t *testing.T) {
	groups := buildOSGroups([]provider.PackageQuery{
		{Ecosystem: "apk", Name: "busybox", Version: "1.36.1-r5", Distro: "alpine-3.18.4"},
		{Ecosystem: "apk", Name: "openssl", Version: "3.1.4-r1", Distro: "alpine-3.18.4"},
		{Ecosystem: "deb", Name: "libssl3", Version: "3.0.11-1~deb12u2", Distro: "debian-12"},
		{Ecosystem: "rpm", Name: "openssl-libs", Version: "1:3.0.7-27.el9", Distro: "redhat-9.4"},
		{Ecosystem: "apk", Name: "no-distro", Version: "1.0"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.11"},
	})
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	byFamily := map[string]osGroup{}
	for _, g := range groups {
		byFamily[g.family] = g
	}
	alpine := byFamily["alpine"]
	if alpine.version != "3.18.4" || alpine.releaseKey != "3.18" || len(alpine.packages) != 2 {
		t.Fatalf("alpine group: %+v", alpine)
	}
	if deb := byFamily["debian"]; deb.releaseKey != "12" || deb.packages[0].Version != "3.0.11-1~deb12u2" {
		t.Fatalf("debian group: %+v", deb)
	}
	rpmGroup := byFamily["redhat"]
	if rpmGroup.releaseKey != "9" {
		t.Fatalf("redhat releaseKey = %q", rpmGroup.releaseKey)
	}
	p := rpmGroup.packages[0]
	if p.Epoch != 1 || p.Version != "3.0.7" || p.Release != "27.el9" || p.SrcName != "openssl-libs" {
		t.Fatalf("rpm pkg split: %+v", p)
	}
}

func TestMapVulnerabilityOSResultCarriesRelease(t *testing.T) {
	refs := map[string]queryRef{"alpine\x00busybox": {ecosystem: "apk", name: "busybox"}}
	mapped, ok := mapVulnerability("alpine", trivyVulnerability{
		VulnerabilityID:  "CVE-2023-42364",
		PkgName:          "busybox",
		InstalledVersion: "1.36.1-r5",
		FixedVersion:     "1.36.1-r6",
		Severity:         "MEDIUM",
	}, refs, "3.18")
	if !ok {
		t.Fatal("expected mapped result")
	}
	rng := mapped.AffectedRanges[0]
	if rng.Ecosystem != "apk" || rng.Release != "3.18" || rng.Fixed != "1.36.1-r6" {
		t.Fatalf("unexpected range: %+v", rng)
	}
}
