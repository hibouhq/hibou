package kev

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Two pages of two, as the real API paginates (shrunk page size is simulated
// by total=4 with 2 items per response and the client's size param ignored).
const euvdPage0 = `{
  "items": [
    {
      "id": "EUVD-2025-00001",
      "description": "Log4Shell, as recorded by the EUVD.",
      "datePublished": "Apr 15, 2025, 8:30:58 PM",
      "exploitedSince": "Apr 20, 2025, 12:00:00 AM",
      "aliases": "GSD-2021-1002352\ncve-2021-44228",
      "enisaIdProduct": [{"product": {"name": "Log4j2"}, "product_version": "2.x"}],
      "enisaIdVendor": [{"vendor": {"name": "Apache"}}]
    },
    {
      "id": "EUVD-2025-00002",
      "description": "Duplicate record for the same CVE; first one wins.",
      "datePublished": "Apr 16, 2025, 9:00:00 AM",
      "aliases": "CVE-2021-44228"
    }
  ],
  "total": 4
}`

const euvdPage1 = `{
  "items": [
    {
      "id": "EUVD-2025-00003",
      "description": "Bare-string product shape, served by older API revisions.",
      "datePublished": "May 1, 2025, 1:02:03 AM",
      "aliases": "CVE-2023-4863",
      "enisaIdProduct": [{"product": "Chromium WebP"}],
      "enisaIdVendor": [{"vendor": "Google"}]
    },
    {
      "id": "EUVD-2025-00004",
      "description": "No CVE alias: cannot match an advisory, skipped.",
      "datePublished": "May 2, 2025, 1:02:03 AM",
      "aliases": "GSD-2025-999"
    }
  ],
  "total": 4
}`

func TestEUVDFetchWalksPagesAndNormalizes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" || r.URL.Query().Get("exploited") != "true" {
			t.Errorf("unexpected request %s", r.URL)
		}
		switch r.URL.Query().Get("page") {
		case "0":
			_, _ = fmt.Fprint(w, euvdPage0)
		case "1":
			_, _ = fmt.Fprint(w, euvdPage1)
		default:
			t.Errorf("walked past the advertised total: page %s", r.URL.Query().Get("page"))
			_, _ = fmt.Fprint(w, `{"items": [], "total": 4}`)
		}
	}))
	defer server.Close()

	source := NewEUVD(server.URL, zerolog.Nop())
	if source.Name() != "euvd" {
		t.Fatalf("name = %q, want euvd", source.Name())
	}
	catalog, err := source.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 4 records: one duplicate CVE collapsed, one CVE-less record skipped.
	if len(catalog.Entries) != 2 || catalog.Skipped != 1 {
		t.Fatalf("entries = %d, skipped = %d; want 2 entries, 1 skipped", len(catalog.Entries), catalog.Skipped)
	}

	log4shell := catalog.Entries[0]
	if log4shell.CVEID != "CVE-2021-44228" {
		t.Errorf("cve id = %q, want CVE-2021-44228 (picked from newline-separated aliases, uppercased)", log4shell.CVEID)
	}
	if log4shell.VulnerabilityName != "EUVD-2025-00001" || log4shell.VendorProject != "Apache" || log4shell.Product != "Log4j2" {
		t.Errorf("entry = %+v, want EUVD id as name with Apache/Log4j2", log4shell)
	}
	// exploitedSince wins over datePublished: it is the "listed as exploited"
	// fact, CISA dateAdded's counterpart.
	if want := time.Date(2025, 4, 20, 0, 0, 0, 0, time.UTC); !log4shell.DateAdded.Equal(want) {
		t.Errorf("date added = %v, want exploitedSince %v", log4shell.DateAdded, want)
	}
	// CISA-only facts stay zero for EUVD rows.
	if !log4shell.DueDate.IsZero() || log4shell.KnownRansomwareCampaignUse {
		t.Errorf("entry = %+v, want no due date and no ransomware flag", log4shell)
	}
	webp := catalog.Entries[1]
	if webp.Product != "Chromium WebP" || webp.VendorProject != "Google" {
		t.Errorf("entry = %+v, want bare-string product/vendor shape decoded", webp)
	}
	// No exploitedSince on this record: publication date is the fallback.
	if want := time.Date(2025, 5, 1, 1, 2, 3, 0, time.UTC); !webp.DateAdded.Equal(want) {
		t.Errorf("date added = %v, want datePublished fallback %v", webp.DateAdded, want)
	}
}

func TestEUVDFetchRejectsIncompleteWalk(t *testing.T) {
	// The server advertises 400 entries but stops serving items after one
	// page: success here would delete the ~300 entries never fetched.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "0" {
			_, _ = fmt.Fprint(w, `{"items": [{"id": "EUVD-2025-1", "aliases": "CVE-2021-44228", "datePublished": "Apr 15, 2025, 8:30:58 PM"}], "total": 400}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"items": [], "total": 400}`)
	}))
	defer server.Close()

	if _, err := NewEUVD(server.URL, zerolog.Nop()).Fetch(context.Background()); err == nil {
		t.Fatal("a walk shorter than the advertised total must be an error, never a smaller catalog")
	}
}

func TestEUVDFetchRejectsMissingTotal(t *testing.T) {
	// A mirror that drops or renames `total` makes completeness unverifiable;
	// trusting one page would silently shrink the catalog to 100 entries.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "0" {
			_, _ = fmt.Fprint(w, `{"items": [{"id": "EUVD-2025-1", "aliases": "CVE-2021-44228", "datePublished": "Apr 15, 2025, 8:30:58 PM"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"items": []}`)
	}))
	defer server.Close()

	if _, err := NewEUVD(server.URL, zerolog.Nop()).Fetch(context.Background()); err == nil {
		t.Fatal("a response with no total must be an error: the walk cannot be verified complete")
	}
}

func TestEUVDFetchRejectsEmptySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"items": [], "total": 0}`)
	}))
	defer server.Close()

	if _, err := NewEUVD(server.URL, zerolog.Nop()).Fetch(context.Background()); err == nil {
		t.Fatal("an empty exploited set must be an error, not a reason to clear the source's rows")
	}
}
