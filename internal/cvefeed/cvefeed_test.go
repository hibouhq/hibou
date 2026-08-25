package cvefeed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, name string) Projection {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	projection, err := Decode(data)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return projection
}

// The motivating record: Apache publishes five inclusive branch bounds and no
// package coordinates, and the CNA's own severity is the string "low" while
// CISA-ADP carries CVSS 9.1.
func TestDecodeTomcatRecord(t *testing.T) {
	got := load(t, "CVE-2026-59084.json")

	if got.ID != "CVE-2026-59084" || got.State != StatePublished {
		t.Fatalf("id/state = %q/%q", got.ID, got.State)
	}
	if got.Assigner != "apache" {
		t.Errorf("assigner = %q, want apache", got.Assigner)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("affected products = %d, want 1", len(got.Affected))
	}

	product := got.Affected[0]
	if product.Product != "Apache Tomcat" || product.ProductKey != "apachetomcat" {
		t.Errorf("product = %q key %q", product.Product, product.ProductKey)
	}
	if product.VendorKey != "apachesoftwarefoundation" {
		t.Errorf("vendor key = %q", product.VendorKey)
	}

	// Every bound Apache publishes is lessThanOrEqual, so every range must be
	// last-affected. A Fixed here would be a fabricated release number.
	if len(product.Ranges) != 5 {
		t.Fatalf("ranges = %d, want 5", len(product.Ranges))
	}
	for _, r := range product.Ranges {
		if r.Fixed != "" {
			t.Errorf("range %+v: Fixed set from an inclusive bound", r)
		}
		if r.LastAffected == "" {
			t.Errorf("range %+v: no upper bound retained", r)
		}
	}
	if product.Ranges[0].Introduced != "11.0.0-M1" || product.Ranges[0].LastAffected != "11.0.23" {
		t.Errorf("first range = %+v", product.Ranges[0])
	}
}

// Severity is chosen by the quality of the statement, not the standing of its
// author: the CNA's textual "low" must lose to the ADP's scored CRITICAL.
func TestSeverityPrefersScoreOverCNAText(t *testing.T) {
	got := load(t, "CVE-2026-59084.json")

	if !got.Severity.Scored() {
		t.Fatal("no scored severity found; CISA-ADP supplies CVSS 3.1 on this record")
	}
	if got.Severity.Score != 9.1 || got.Severity.Label != "critical" {
		t.Errorf("severity = %.1f %q, want 9.1 critical", got.Severity.Score, got.Severity.Label)
	}
	if got.Severity.Source != "CISA-ADP" {
		t.Errorf("severity source = %q, want CISA-ADP", got.Severity.Source)
	}
	if !strings.HasPrefix(got.Severity.Vector, "CVSS:3.1/") {
		t.Errorf("vector = %q", got.Severity.Vector)
	}
}

// A withdrawn record must decode, not vanish: findings derived from it have to
// be retired, which is impossible if ingestion drops it.
func TestRejectedRecordDecodes(t *testing.T) {
	got := load(t, "rejected.json")

	if got.State != StateRejected {
		t.Fatalf("state = %q, want %s", got.State, StateRejected)
	}
	if !got.Withdrawn() {
		t.Error("Withdrawn() = false for a REJECTED record")
	}
	if got.ID == "" {
		t.Error("rejected record decoded without an id")
	}
}

// "n/a" is used where a field should have been omitted; matching on it would
// join unrelated products under one key.
func TestPlaceholderVendorIsDropped(t *testing.T) {
	got := load(t, "placeholder-vendor.json")

	for _, product := range got.Affected {
		if IsPlaceholder(product.Product) {
			t.Errorf("kept placeholder product %q", product.Product)
		}
		if product.Vendor != "" && IsPlaceholder(product.Vendor) {
			t.Errorf("kept placeholder vendor %q", product.Vendor)
		}
	}
}

func TestDecodeRejectsOversizedRecord(t *testing.T) {
	if _, err := Decode(make([]byte, MaxRecordBytes+1)); err == nil {
		t.Fatal("oversized record accepted")
	}
}

func TestDecodeRejectsRecordWithoutID(t *testing.T) {
	if _, err := Decode([]byte(`{"cveMetadata":{"state":"PUBLISHED"}}`)); err == nil {
		t.Fatal("record without cveId accepted")
	}
}

// The three bound kinds are not interchangeable, and only a wildcard with no
// upper bound is dropped — a bare version names one exact affected release and
// is the corpus's most common shape.
func TestRangeBounds(t *testing.T) {
	const doc = `{"cveMetadata":{"cveId":"CVE-0000-1","state":"PUBLISHED"},
	  "containers":{"cna":{"affected":[{"vendor":"Acme","product":"Widget","versions":[
	    {"status":"affected","version":"1.0","lessThanOrEqual":"1.9"},
	    {"status":"affected","version":"2.0","lessThan":"2.5"},
	    {"status":"affected","version":"3.0"},
	    {"status":"affected","version":"*"},
	    {"status":"unaffected","version":"4.0","lessThan":"4.9"}]}]}}}`

	got, err := Decode([]byte(doc))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	ranges := got.Affected[0].Ranges
	if len(ranges) != 3 {
		t.Fatalf("ranges = %d, want 3 (wildcard and unaffected dropped): %+v", len(ranges), ranges)
	}
	if ranges[0].LastAffected != "1.9" || ranges[0].Fixed != "" {
		t.Errorf("inclusive bound became %+v", ranges[0])
	}
	if ranges[1].Fixed != "2.5" || ranges[1].LastAffected != "" {
		t.Errorf("exclusive bound became %+v", ranges[1])
	}
	// An exact version is a point interval, not an open one.
	if ranges[2].Introduced != "3.0" || ranges[2].LastAffected != "3.0" || ranges[2].Fixed != "" {
		t.Errorf("bare version became %+v, want the point 3.0..3.0", ranges[2])
	}
}

// A wildcard with no upper bound is the one genuinely open statement, and it
// must never survive: it would match every future release of the product.
func TestWildcardVersionIsDropped(t *testing.T) {
	for _, wildcard := range []string{"*", "0", "-"} {
		doc := `{"cveMetadata":{"cveId":"CVE-0000-2","state":"PUBLISHED"},
		  "containers":{"cna":{"affected":[{"product":"Widget","versions":[
		    {"status":"affected","version":"` + wildcard + `"}]}]}}}`
		got, err := Decode([]byte(doc))
		if err != nil {
			t.Fatalf("decode %q: %v", wildcard, err)
		}
		if len(got.Affected) != 0 {
			t.Errorf("wildcard %q produced %+v", wildcard, got.Affected)
		}
	}
}

func TestProductKey(t *testing.T) {
	// The real inconsistency this collapses, observed in one hour of the feed.
	for _, pair := range [][2]string{
		{"Lodash", "lodash"},
		{"Apache Tomcat", "apache tomcat"},
		{"Erlang/OTP", "erlang otp"},
		{"NGINX Plus", "nginx-plus"},
	} {
		if ProductKey(pair[0]) != ProductKey(pair[1]) {
			t.Errorf("ProductKey(%q)=%q != ProductKey(%q)=%q",
				pair[0], ProductKey(pair[0]), pair[1], ProductKey(pair[1]))
		}
	}
	// Distinct products must stay distinct.
	if ProductKey("Apache Tomcat") == ProductKey("Apache Struts") {
		t.Error("distinct products collapsed to one key")
	}
}

func TestIsPlaceholder(t *testing.T) {
	for _, value := range []string{"", "n/a", "N/A", "unknown", "  none  "} {
		if !IsPlaceholder(value) {
			t.Errorf("IsPlaceholder(%q) = false", value)
		}
	}
	if IsPlaceholder("Apache Tomcat") {
		t.Error("real product treated as placeholder")
	}
}
