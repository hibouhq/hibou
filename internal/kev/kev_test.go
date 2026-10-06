package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

const sampleCatalog = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.10.06",
  "dateReleased": "2026-10-06T14:00:00.000Z",
  "count": 3,
  "vulnerabilities": [
    {
      "cveID": "cve-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Log4Shell.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    },
    {
      "cveID": "CVE-2023-4863",
      "vendorProject": "Google",
      "product": "Chromium WebP",
      "vulnerabilityName": "Google Chromium WebP Heap-Based Buffer Overflow Vulnerability",
      "dateAdded": "2023-09-13",
      "dueDate": "2023-10-04",
      "knownRansomwareCampaignUse": "Unknown"
    },
    {
      "cveID": "not-a-cve",
      "vendorProject": "Broken",
      "product": "Entry",
      "vulnerabilityName": "Malformed upstream row",
      "dateAdded": "2024-01-01",
      "dueDate": "2024-01-22",
      "knownRansomwareCampaignUse": "Unknown"
    }
  ]
}`

func TestFetchNormalizesCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got == "" {
			t.Error("expected a User-Agent header")
		}
		_, _ = w.Write([]byte(sampleCatalog))
	}))
	defer server.Close()

	catalog, err := NewCISA(server.URL, zerolog.Nop()).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Version != "2026.10.06" {
		t.Errorf("version = %q, want 2026.10.06", catalog.Version)
	}
	if len(catalog.Entries) != 2 || catalog.Skipped != 1 {
		t.Fatalf("entries = %d, skipped = %d; want 2 entries, 1 skipped", len(catalog.Entries), catalog.Skipped)
	}

	log4shell := catalog.Entries[0]
	// Lowercase upstream id is normalized so DB lookups stay a plain equality.
	if log4shell.CVEID != "CVE-2021-44228" {
		t.Errorf("cve id = %q, want CVE-2021-44228", log4shell.CVEID)
	}
	if !log4shell.KnownRansomwareCampaignUse {
		t.Error("log4shell ransomware use should be true for \"Known\"")
	}
	if want := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC); !log4shell.DateAdded.Equal(want) {
		t.Errorf("date added = %v, want %v", log4shell.DateAdded, want)
	}
	if catalog.Entries[1].KnownRansomwareCampaignUse {
		t.Error("webp ransomware use should be false for \"Unknown\"")
	}
}

func TestFetchRejectsEmptyCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"x","count":0,"vulnerabilities":[]}`))
	}))
	defer server.Close()

	if _, err := NewCISA(server.URL, zerolog.Nop()).Fetch(context.Background()); err == nil {
		t.Fatal("an empty catalog must be an error, not a reason to clear the table")
	}
}

func TestFetchRejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	if _, err := NewCISA(server.URL, zerolog.Nop()).Fetch(context.Background()); err == nil {
		t.Fatal("non-200 must be an error")
	}
}
