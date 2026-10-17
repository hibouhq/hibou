package advisorydb

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWriteReadMatch(t *testing.T) {
	var buf bytes.Buffer
	exported := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	w, err := NewWriter(&buf, Header{ExportedAt: exported, Org: "github/acme", Ecosystems: []string{"npm", "deb"}})
	if err != nil {
		t.Fatal(err)
	}
	score := 9.8
	epss := 0.42
	records := []Record{
		{ID: "a1", CanonicalID: "GHSA-1111", Title: "Prototype pollution", KEV: true, EPSS: &epss,
			Ratings: []Rating{{Rater: "nvd", Version: "v3.1", Score: &score, Provider: "osv"}},
			Ranges:  []Range{{Ecosystem: "npm", Package: "lodash", Introduced: "0", Fixed: "4.17.21"}}},
		{ID: "a2", CanonicalID: "GHSA-2222", Withdrawn: true,
			Ranges: []Range{{Ecosystem: "npm", Package: "lodash", Introduced: "0"}}},
		{ID: "a3", CanonicalID: "MAL-0001", IsMalware: true, MalwareType: "malicious",
			Ranges: []Range{{Ecosystem: "npm", Package: "lodahs", Introduced: "0"}}},
		{ID: "a4", CanonicalID: "DSA-5555", Ratings: []Rating{{Rater: "debian", Label: "high"}},
			Ranges: []Range{{Ecosystem: "deb", Package: "openssl", Introduced: "0", Fixed: "3.0.11-1~deb12u2", Release: "12"}}},
	}
	for _, record := range records {
		if err := w.Write(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if w.Records() != 4 || strings.Count(buf.String(), "\n") != 5 {
		t.Fatalf("wrote %d records, %q", w.Records(), buf.String())
	}

	db, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if db.Advisories() != 4 || db.Header.Org != "github/acme" || !db.Header.ExportedAt.Equal(exported) {
		t.Errorf("header %+v, records %d", db.Header, db.Advisories())
	}
	if !db.Stale(exported.Add(8*24*time.Hour)) || db.Stale(exported.Add(time.Hour)) {
		t.Error("staleness")
	}

	match := db.Match("pkg:npm/lodash@4.17.20")
	if !match.Supported || len(match.Advisories) != 1 {
		t.Fatalf("lodash: %+v", match)
	}
	got := match.Advisories[0]
	if got.CanonicalID != "GHSA-1111" || got.Severity != "critical" || got.CVSS == nil || *got.CVSS != 9.8 || got.RatedBy != "nvd" || !got.KEV || got.EPSS == nil || len(got.FixedVersions) != 1 || got.FixedVersions[0] != "4.17.21" {
		t.Errorf("lodash advisory %+v", got)
	}
	if fixed := db.Match("pkg:npm/lodash@4.17.21"); len(fixed.Advisories) != 0 {
		t.Errorf("fixed version matched %+v", fixed.Advisories)
	}
	if malware := db.Match("pkg:npm/lodahs@1.0.0"); len(malware.Advisories) != 1 || !malware.Advisories[0].IsMalware || malware.Advisories[0].Severity != "critical" {
		t.Errorf("malware %+v", malware)
	}
	// A distribution range applies to its release only.
	if deb := db.Match("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12"); len(deb.Advisories) != 1 || deb.Advisories[0].Severity != "high" {
		t.Errorf("debian 12 %+v", deb)
	}
	if deb := db.Match("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-11"); len(deb.Advisories) != 0 {
		t.Errorf("debian 11 must not match a bookworm range: %+v", deb)
	}
	if unsupported := db.Match("pkg:npm/lodash"); unsupported.Supported {
		t.Error("a purl without version is not supported")
	}
	if unknown := db.Match("pkg:npm/nothing@1.0.0"); !unknown.Supported || len(unknown.Advisories) != 0 {
		t.Errorf("unknown package %+v", unknown)
	}

	if _, err := Read(strings.NewReader(`{"format":"other","version":1}` + "\n")); err == nil {
		t.Error("foreign format accepted")
	}
	if _, err := Read(strings.NewReader(`{"format":"hibou-advisory-db","version":99}` + "\n")); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("newer version: %v", err)
	}
}
