package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// End-to-end over the real schema: decode a published record, store it, and
// check a subscription written under the CNA's own product name finds it.
func TestCVEFeedRoundTrip(t *testing.T) {
	db := openStoreTestDB(t, "cve feed round trip")
	queries := NewQueries(db)
	ctx := context.Background()

	raw, err := os.ReadFile(filepath.Join("..", "cvefeed", "testdata", "CVE-2026-59084.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	record, err := cvefeed.Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM cve_records WHERE cve_id = $1`, record.ID)
		_, _ = db.ExecContext(ctx, `DELETE FROM cve_subscriptions WHERE label = 'Apache Tomcat (test)'`)
	})

	if err := queries.SaveCVERecord(ctx, db, record); err != nil {
		t.Fatalf("SaveCVERecord: %v", err)
	}

	// The five branch bounds Apache publishes must all survive the round trip.
	products, err := queries.db.ListCVEAffectedProducts(ctx, record.ID)
	if err != nil {
		t.Fatalf("ListCVEAffectedProducts: %v", err)
	}
	if len(products) != 5 {
		t.Fatalf("stored %d affected rows, want 5", len(products))
	}
	for _, product := range products {
		if product.ProductKey != "apachetomcat" {
			t.Errorf("product key = %q", product.ProductKey)
		}
		// Every Apache bound is inclusive, so none may have become a fixed
		// version — that would name a release nobody verified exists.
		if product.Fixed != "" {
			t.Errorf("row %+v gained a fixed version from an inclusive bound", product)
		}
		if product.LastAffected == "" {
			t.Errorf("row %+v lost its upper bound", product)
		}
	}

	// Severity came from CISA-ADP, not from the CNA's textual "low".
	stored, err := queries.db.GetCVERecord(ctx, record.ID)
	if err != nil {
		t.Fatalf("GetCVERecord: %v", err)
	}
	if stored.Severity != "critical" {
		t.Errorf("stored severity = %q, want critical", stored.Severity)
	}
	if !stored.CvssScore.Valid || stored.CvssScore.String != "9.10" {
		t.Errorf("stored score = %+v, want 9.10", stored.CvssScore)
	}

	// A subscription under the CNA's own product name finds it.
	subscription, err := queries.db.CreateCVESubscription(ctx, createSubscriptionParams(t, "Apache Tomcat (test)", []string{"apachetomcat"}))
	if err != nil {
		t.Fatalf("CreateCVESubscription: %v", err)
	}
	matched, err := queries.MatchSubscriptions(ctx, []string{"apachetomcat"}, []string{"apachesoftwarefoundation"})
	if err != nil {
		t.Fatalf("MatchSubscriptions: %v", err)
	}
	if !containsSubscription(matched, subscription.ID.String()) {
		t.Fatal("a subscription on the CNA's own product name did not match the record")
	}

	// The preview: proof the alias catches something, before committing to it.
	rows, total, err := queries.PreviewSubscription(ctx, []string{"apachetomcat"}, 10)
	if err != nil {
		t.Fatalf("PreviewSubscription: %v", err)
	}
	if total < 1 || len(rows) < 1 {
		t.Fatalf("preview found %d rows / %d total, want at least one", len(rows), total)
	}

	// A wrong alias must come back empty rather than quietly matching nothing
	// that looks the same as matching everything.
	_, emptyTotal, err := queries.PreviewSubscription(ctx, []string{"apacheutomcat"}, 10)
	if err != nil {
		t.Fatalf("PreviewSubscription(typo): %v", err)
	}
	if emptyTotal != 0 {
		t.Errorf("a misspelled alias matched %d records", emptyTotal)
	}

	// Queueing is idempotent: the same record arriving twice is one decision.
	for range 2 {
		if err := queries.QueueTriageItem(ctx, subscription.ID, record.ID); err != nil {
			t.Fatalf("QueueTriageItem: %v", err)
		}
	}
	pending, err := queries.db.CountPendingTriageItems(ctx)
	if err != nil {
		t.Fatalf("CountPendingTriageItems: %v", err)
	}
	if pending < 1 {
		t.Fatalf("pending = %d, want at least 1", pending)
	}
}

// A timeline entry must be storable with no actor: most of what it carries is
// upstream activity nobody here caused.
func TestAdvisoryEventWithoutActor(t *testing.T) {
	db := openStoreTestDB(t, "advisory event")
	queries := NewQueries(db)
	ctx := context.Background()

	detail, _ := json.Marshal(RangeChange{Product: "Apache Tomcat", Before: "9.0.13", After: "9.0.0.M1"})
	event := AdvisoryEvent{
		CVEID:      "CVE-2026-59084",
		Kind:       EventCNARevised,
		OccurredAt: time.Now().UTC(),
		Detail:     detail,
	}
	if err := queries.RecordAdvisoryEvent(ctx, event); err != nil {
		t.Fatalf("RecordAdvisoryEvent: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM advisory_events WHERE cve_id = $1`, event.CVEID)
	})

	if !EventCNARevised.External() {
		t.Error("cna_revised is not marked as an upstream event")
	}
	if EventAuthored.External() {
		t.Error("coordinates_authored is marked as an upstream event")
	}
}

func createSubscriptionParams(t *testing.T, label string, productKeys []string) dbgen.CreateCVESubscriptionParams {
	t.Helper()
	return dbgen.CreateCVESubscriptionParams{
		Label:       label,
		ProductKeys: productKeys,
		VendorKeys:  []string{},
	}
}

func containsSubscription(subscriptions []dbgen.CveSubscription, id string) bool {
	for _, subscription := range subscriptions {
		if subscription.ID.String() == id {
			return true
		}
	}
	return false
}

// A "published" event carries no detail. A nil RawMessage binds as SQL NULL,
// not the column default, so detail-less events were rejected by the NOT NULL
// constraint and silently dropped from the activity stream.
func TestRecordAdvisoryEventWithoutDetail(t *testing.T) {
	db := openStoreTestDB(t, "advisory event without detail")
	queries := NewQueries(db)
	ctx := context.Background()

	const cveID = "CVE-2099-20001"
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM advisory_events WHERE cve_id = $1`, cveID)
	})

	if err := queries.RecordAdvisoryEvent(ctx, AdvisoryEvent{
		CVEID:      cveID,
		Kind:       EventPublished,
		OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordAdvisoryEvent with nil detail: %v", err)
	}
	var detail string
	if err := db.QueryRowContext(ctx, `SELECT detail::text FROM advisory_events WHERE cve_id = $1`, cveID).Scan(&detail); err != nil {
		t.Fatalf("read back event: %v", err)
	}
	if detail != "{}" {
		t.Fatalf("detail = %q, want {}", detail)
	}
}
