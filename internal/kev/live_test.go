//go:build live

package kev

// Live smoke tests against the real catalog endpoints. Excluded from CI and
// `make test` by the build tag; run on demand when the upstream wire format is
// in doubt:
//
//	go test -tags live -run Live ./internal/kev/
//
// They assert only what a format drift would break — entries decode, CVE ids
// come out, dates parse — never exact counts, which change daily.

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
)

func TestLiveCISAFetch(t *testing.T) {
	catalog, err := NewCISA("", zerolog.Nop()).Fetch(context.Background())
	if err != nil {
		t.Fatalf("live CISA fetch: %v", err)
	}
	// ~1,400 entries in 2026; a drastic drop means the parse went wrong.
	if len(catalog.Entries) < 1000 {
		t.Fatalf("entries = %d, want >= 1000; wire format may have drifted", len(catalog.Entries))
	}
	if catalog.Version == "" {
		t.Error("catalog version empty; wire format may have drifted")
	}
	dated := 0
	for _, entry := range catalog.Entries {
		if !entry.DateAdded.IsZero() {
			dated++
		}
	}
	if dated < len(catalog.Entries)*9/10 {
		t.Errorf("only %d/%d entries carry a date added; date format may have drifted", dated, len(catalog.Entries))
	}
}

func TestLiveEUVDFetch(t *testing.T) {
	catalog, err := NewEUVD("", zerolog.Nop()).Fetch(context.Background())
	if err != nil {
		t.Fatalf("live EUVD fetch: %v", err)
	}
	// The exploited set is several hundred entries; single digits means the
	// pagination or the exploited filter broke.
	if len(catalog.Entries) < 100 {
		t.Fatalf("entries = %d, want >= 100; pagination or filter may have drifted", len(catalog.Entries))
	}
	dated := 0
	for _, entry := range catalog.Entries {
		if entry.CVEID == "" {
			t.Fatalf("entry with empty CVE id survived normalization: %+v", entry)
		}
		if !entry.DateAdded.IsZero() {
			dated++
		}
	}
	if dated < len(catalog.Entries)/2 {
		t.Errorf("only %d/%d entries carry a date; exploitedSince/datePublished format may have drifted", dated, len(catalog.Entries))
	}
	t.Logf("live EUVD: %d entries, %d skipped (no CVE alias), %d dated", len(catalog.Entries), catalog.Skipped, dated)
}
