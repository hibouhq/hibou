package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/cvefeed"
)

// The dogfood failure this reproduces: a watch on "apache tomcat" showed
// "never matched" while CVE-2026-59083 — vendor "Apache Software Foundation",
// product "Apache Tomcat", published weeks earlier, no package coordinates —
// sat in the stored corpus. The sweeper only visits records the feed revises,
// and the seed deliberately queues nothing, so a record already in the corpus
// was unreachable by any watch created after it, forever, unless its vendor
// happened to revise it.
func TestCreateWatchBackfillsFromStoredCorpus(t *testing.T) {
	t.Parallel()

	srv, _, admin, _ := newDiscoveryTestServer(t)
	srv.cfg = config.Config{InstanceAdmins: []string{admin.Email}}
	srv.log = zerolog.Nop()
	ctx := context.Background()

	suffix := uuid.NewString()[:8]
	productKey := "apachetomcat" + suffix
	record := func(id, state string, published time.Time, vendorKey string) cvefeed.Projection {
		return cvefeed.Projection{
			ID:        id,
			State:     state,
			Published: published,
			Updated:   published,
			Affected: []cvefeed.AffectedProduct{{
				Vendor:     "Apache Software Foundation",
				Product:    "Apache Tomcat",
				VendorKey:  vendorKey,
				ProductKey: productKey,
				// The decoder never emits a range-less product (collectAffected
				// drops them), and the store's affected insert iterates ranges —
				// a fixture without one writes no matchable row at all. Mirrors
				// CVE-2026-59083's real shape: lessThanOrEqual bounds.
				Ranges: []cvefeed.VersionRange{{
					Introduced:   "9.0.0.M1",
					LastAffected: "9.0.119",
				}},
			}},
			CWEs:        []string{},
			References:  []string{},
			Description: "test record",
		}
	}

	now := time.Now().UTC()
	stored := []cvefeed.Projection{
		// The CVE-2026-59083 stand-in: published before the watch, matching keys.
		record("CVE-2026-2"+suffix[:4], "PUBLISHED", now.AddDate(0, -1, 0), "apachesoftwarefoundation"+suffix),
		record("CVE-2025-2"+suffix[:4], "PUBLISHED", now.AddDate(-1, 0, 0), "apachesoftwarefoundation"+suffix),
		// Withdrawn: there is nothing to decide, so it must not queue.
		record("CVE-2024-2"+suffix[:4], "REJECTED", now.AddDate(-2, 0, 0), "apachesoftwarefoundation"+suffix),
	}
	if err := srv.queries.SaveCVERecords(ctx, srv.db, stored); err != nil {
		t.Fatalf("SaveCVERecords: %v", err)
	}

	createWatch := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/instance/advisories/watches", strings.NewReader(body))
		request = request.WithContext(auth.WithUser(request.Context(), admin))
		recorder := httptest.NewRecorder()
		srv.handleCreateWatch(recorder, request)
		var envelope struct {
			Data map[string]any `json:"data"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &envelope)
		return recorder, envelope.Data
	}

	recorder, watch := createWatch(`{"label":"Apache Tomcat","product_keys":["` + productKey + `"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create watch = %d: %s", recorder.Code, recorder.Body.String())
	}

	// The response must not say "never matched" beside a non-zero queue.
	if watch["last_matched_at"] == nil {
		t.Error("create response reports last_matched_at null after a successful backfill")
	}

	// Both published records queued; the withdrawn one not.
	if pending, _ := watch["pending_triage"].(float64); int(pending) != 2 {
		t.Errorf("pending_triage = %v, want 2 (published matches, withdrawn excluded)", watch["pending_triage"])
	}

	var queued int
	if err := srv.db.QueryRowContext(ctx,
		`SELECT count(*) FROM cve_triage_items t JOIN cve_subscriptions s ON s.id = t.subscription_id
		 WHERE s.product_keys && ARRAY[$1]::text[] AND t.state = 'pending'`, productKey,
	).Scan(&queued); err != nil {
		t.Fatalf("count queue: %v", err)
	}
	if queued != 2 {
		t.Errorf("queued = %d, want 2", queued)
	}

	// "Last matched: never" would be a lie after a successful backfill.
	var lastMatched *time.Time
	if err := srv.db.QueryRowContext(ctx,
		`SELECT last_matched_at FROM cve_subscriptions WHERE product_keys && ARRAY[$1]::text[]`, productKey,
	).Scan(&lastMatched); err != nil {
		t.Fatalf("read last_matched_at: %v", err)
	}
	if lastMatched == nil {
		t.Error("last_matched_at still NULL after the backfill matched two records")
	}

	// Vendor narrowing must mirror the sweeper: a watch pinned to a different
	// vendor matches nothing, and its pending count says so.
	recorder, narrowed := createWatch(`{"label":"Someone Else's Tomcat","product_keys":["` + productKey + `"],"vendor_keys":["someothervendor` + suffix + `"]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create narrowed watch = %d: %s", recorder.Code, recorder.Body.String())
	}
	if pending, _ := narrowed["pending_triage"].(float64); int(pending) != 0 {
		t.Errorf("vendor-narrowed pending_triage = %v, want 0", narrowed["pending_triage"])
	}
}
