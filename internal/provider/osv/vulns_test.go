package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

// The failure this guards is total, not partial. OSV serves a CVE ID from its
// own CVE ecosystem, where affected[].package is null and the ranges are GIT
// commits — the real coordinates are on the aliased advisory. A lookup that
// stopped at the CVE record would report "upstream publishes no coordinates"
// for every advisory ever checked, which is indistinguishable from the answer
// that means the feature is working.
func TestPackagesForVulnFollowsAliasesToTheReviewedRecord(t *testing.T) {
	// The shapes are the ones api.osv.dev really returns for CVE-2021-44228 and
	// GHSA-jfh8-c2jp-5v3q, trimmed to the fields read here.
	records := map[string]string{
		"/v1/vulns/CVE-2021-44228": `{
			"id": "CVE-2021-44228",
			"aliases": ["GHSA-jfh8-c2jp-5v3q"],
			"affected": [{"ranges": [{"type": "GIT"}]}]
		}`,
		"/v1/vulns/GHSA-jfh8-c2jp-5v3q": `{
			"id": "GHSA-jfh8-c2jp-5v3q",
			"affected": [
				{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}},
				{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}},
				{"package": {"ecosystem": "Maven", "name": "com.guicedee.services:log4j-core"}}
			]
		}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := records[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	provider := New(server.URL, zerolog.Nop())
	coordinates, err := provider.PackagesForVuln(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("PackagesForVuln: %v", err)
	}
	// Deduplicated across the alias: three entries, two distinct packages.
	if len(coordinates) != 2 {
		t.Fatalf("got %d coordinates, want 2 distinct: %+v", len(coordinates), coordinates)
	}
	for _, coordinate := range coordinates {
		if coordinate.Ecosystem != "maven" {
			t.Errorf("ecosystem = %q, want the internal spelling", coordinate.Ecosystem)
		}
	}
}

// An ID OSV does not serve is the ordinary case for an advisory nobody has
// mapped upstream. Reporting it as an error would make the divergence pass count
// every such advisory as a broken lookup.
func TestPackagesForVulnTreatsAnUnknownIDAsNoCoordinates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	coordinates, err := New(server.URL, zerolog.Nop()).PackagesForVuln(context.Background(), "CVE-2026-59084")
	if err != nil {
		t.Fatalf("PackagesForVuln: %v", err)
	}
	if len(coordinates) != 0 {
		t.Fatalf("got %+v, want none", coordinates)
	}
}

// A record with coordinates of its own is used as-is: following aliases from
// there would pull in packages the reviewed advisory deliberately excluded.
func TestPackagesForVulnDoesNotFollowAliasesWhenTheRecordHasPackages(t *testing.T) {
	var aliasRequested bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vulns/GHSA-other" {
			aliasRequested = true
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "GHSA-direct",
			"aliases": []string{"GHSA-other"},
			"affected": []map[string]any{
				{"package": map[string]string{"ecosystem": "npm", "name": "left-pad"}},
			},
		})
	}))
	defer server.Close()

	coordinates, err := New(server.URL, zerolog.Nop()).PackagesForVuln(context.Background(), "GHSA-direct")
	if err != nil {
		t.Fatalf("PackagesForVuln: %v", err)
	}
	if len(coordinates) != 1 || coordinates[0].Name != "left-pad" {
		t.Fatalf("got %+v, want only the record's own package", coordinates)
	}
	if aliasRequested {
		t.Error("followed an alias despite the record naming packages itself")
	}
}

// OSV qualifies distro ecosystems with a release ("Debian:12"). The release is
// not part of the coordinate identity, and leaving it on would diverge a mapping
// every time upstream added a second release of the same package.
func TestPackagesForVulnStripsTheDistroReleaseQualifier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "DSA-1",
			"affected": []map[string]any{
				{"package": map[string]string{"ecosystem": "Debian:12", "name": "tomcat10"}},
				{"package": map[string]string{"ecosystem": "Debian:11", "name": "tomcat10"}},
			},
		})
	}))
	defer server.Close()

	coordinates, err := New(server.URL, zerolog.Nop()).PackagesForVuln(context.Background(), "DSA-1")
	if err != nil {
		t.Fatalf("PackagesForVuln: %v", err)
	}
	if len(coordinates) != 1 || coordinates[0].Ecosystem != "deb" {
		t.Fatalf("got %+v, want one deb coordinate", coordinates)
	}
}
