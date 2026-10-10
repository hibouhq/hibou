package server

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestFindingKEVIncludesSourceRecordIdentifiersAndEUVDAdvisoryAlias(t *testing.T) {
	t.Parallel()

	srv, _, _, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	canonicalID := "GHSA-detail-" + uuid.NewString()
	advisory, err := upsertRatedAdvisory(ctx, srv.queries, dbgen.UpsertAdvisoryParams{
		CanonicalID: canonicalID, Title: "detail",
	}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelHigh})
	if err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
	cveID := "CVE-2099-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	euvdID := "EUVD-" + cveID[len("CVE-"):]
	if err := srv.queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisory.ID, Alias: cveID}); err != nil {
		t.Fatalf("UpsertAdvisoryAlias: %v", err)
	}
	seedKEVEntries(t, srv, "cisa", []kev.Entry{{CVEID: cveID}})
	seedKEVEntries(t, srv, "euvd", []kev.Entry{{CVEID: cveID, VulnerabilityName: " " + strings.ToLower(euvdID) + " "}})

	detail := srv.advisoryDetail(ctx, advisory)
	if !reflect.DeepEqual(detail.Aliases, []string{cveID, euvdID}) {
		t.Fatalf("detail aliases = %v, want CVE and EUVD aliases", detail.Aliases)
	}
	response := srv.findingKEV(ctx, &store.Vulnerability{Type: "dependency", AdvisoryID: &advisory.ID}, detail)
	if response == nil {
		t.Fatal("findingKEV = nil, want catalog records")
	}
	wantEntries := []findingKEVEntryResponse{
		{Source: "cisa", Identifier: cveID, CVEID: cveID},
		{Source: "euvd", Identifier: euvdID, CVEID: cveID},
	}
	if !reflect.DeepEqual(response.Entries, wantEntries) {
		t.Fatalf("entries = %#v, want %#v", response.Entries, wantEntries)
	}
	identifierOnly := srv.findingKEV(ctx, &store.Vulnerability{
		Type:                   "dependency",
		PrimaryIdentifierValue: cveID,
	}, nil)
	if identifierOnly == nil || !reflect.DeepEqual(identifierOnly.Entries, wantEntries) {
		t.Fatalf("identifier-only entries = %#v, want %#v", identifierOnly, wantEntries)
	}
}

func TestKEVEntryIdentifierRejectsInvalidEUVDIdentifier(t *testing.T) {
	if _, ok := kevEntryIdentifier(dbgen.KevEntry{Source: "euvd", CveID: "CVE-2026-73069", VulnerabilityName: "EUVD-invalid"}); ok {
		t.Fatal("kevEntryIdentifier accepted malformed EUVD identifier")
	}
	if got, ok := kevEntryIdentifier(dbgen.KevEntry{Source: "cisa", CveID: "CVE-2026-73069"}); !ok || got != "CVE-2026-73069" {
		t.Fatalf("kevEntryIdentifier(cisa) = %q, %t", got, ok)
	}
}

func TestFindingKEVPreservesSourceWithInvalidRecordIdentifier(t *testing.T) {
	t.Parallel()
	srv, _, _, _ := newDiscoveryTestServer(t)
	cveID := "CVE-2099-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	seedKEVEntries(t, srv, "euvd", []kev.Entry{{CVEID: cveID, VulnerabilityName: "EUVD-invalid"}})
	response := srv.findingKEV(t.Context(), &store.Vulnerability{Type: "dependency", PrimaryIdentifierValue: cveID}, nil)
	if response == nil || !reflect.DeepEqual(response.Sources, []string{"euvd"}) || len(response.Entries) != 0 {
		t.Fatalf("findingKEV = %#v, want EUVD membership without invalid identifier", response)
	}
}

func seedKEVEntries(t *testing.T, srv *Server, source string, entries []kev.Entry) {
	t.Helper()
	for _, entry := range entries {
		if _, err := srv.db.ExecContext(t.Context(), `
			INSERT INTO kev_entries (
				source, cve_id, vendor_project, product, vulnerability_name,
				date_added, due_date, known_ransomware_campaign_use, updated_at
			) VALUES ($1, $2, $3, $4, $5, nullif($6, '')::date, nullif($7, '')::date, $8, now())
			ON CONFLICT (source, cve_id) DO UPDATE SET
				vendor_project = EXCLUDED.vendor_project,
				product = EXCLUDED.product,
				vulnerability_name = EXCLUDED.vulnerability_name,
				date_added = EXCLUDED.date_added,
				due_date = EXCLUDED.due_date,
				known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
				updated_at = now()`,
			source, entry.CVEID, entry.VendorProject, entry.Product, entry.VulnerabilityName,
			formatKEVTestDate(entry.DateAdded), formatKEVTestDate(entry.DueDate), entry.KnownRansomwareCampaignUse,
		); err != nil {
			t.Fatalf("upsert KEV fixture %s/%s: %v", source, entry.CVEID, err)
		}
	}
	t.Cleanup(func() {
		for _, entry := range entries {
			if _, err := srv.db.ExecContext(context.Background(), `DELETE FROM kev_entries WHERE source = $1 AND cve_id = $2`, source, entry.CVEID); err != nil {
				t.Errorf("remove KEV fixture %s/%s: %v", source, entry.CVEID, err)
			}
		}
	})
}

func formatKEVTestDate(date time.Time) string {
	if date.IsZero() {
		return ""
	}
	return date.UTC().Format("2006-01-02")
}
