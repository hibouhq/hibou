package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
)

// A sweep that fails must say so where a sweep that works reports its counts.
// Left to the logs alone, a feed that has been unable to reach the CVE list
// since the pod started is indistinguishable in the UI from a feed with nothing
// to report — which is the silent-nothing failure the feature exists to prevent.
func TestRecordCVEFeedFailureIsVisibleAndKeepsTheLastSuccess(t *testing.T) {
	t.Parallel()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	srv := &Server{db: db, queries: store.NewQueries(db), log: zerolog.Nop()}
	ctx := context.Background()

	// A pass that worked, as the sweep would have written it.
	success := FeedHealth{At: "2026-08-25T09:00:00Z", Revision: "abc123", Seen: 1300, Queued: 2}
	encoded, err := json.Marshal(success)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.queries.SetInstanceSettingValue(ctx, feedHealthKey, encoded); err != nil {
		t.Fatalf("seed health: %v", err)
	}

	srv.recordCVEFeedFailure(ctx, errors.New("mkdir /tmp/hibou-cvelist: read-only file system"))

	health := readFeedHealth(t, srv, ctx)
	if health.Error == "" {
		t.Fatal("a failed sweep left no trace in feed health")
	}
	if health.FailingSince == "" {
		t.Error("FailingSince unset, so the reader cannot tell how long it has been broken")
	}
	// The counts from the last working pass survive: "last worked at X, failing
	// since Y" is the report, not one or the other.
	if health.Seen != 1300 || health.Revision != "abc123" || health.At != success.At {
		t.Errorf("failure discarded the last successful pass: %+v", health)
	}

	// A second failure does not restart the clock — the question is how long
	// this has been broken, not when it was last retried.
	firstFailure := health.FailingSince
	srv.recordCVEFeedFailure(ctx, errors.New("still broken"))
	again := readFeedHealth(t, srv, ctx)
	if again.FailingSince != firstFailure {
		t.Errorf("FailingSince moved from %q to %q; it must mark the start of the run",
			firstFailure, again.FailingSince)
	}
	if again.Error != "still broken" {
		t.Errorf("Error = %q, want the most recent reason", again.Error)
	}
}

func readFeedHealth(t *testing.T, srv *Server, ctx context.Context) FeedHealth {
	t.Helper()
	raw, err := srv.queries.GetInstanceSettingValue(ctx, feedHealthKey)
	if err != nil {
		t.Fatalf("read health: %v", err)
	}
	var health FeedHealth
	if err := json.Unmarshal(raw, &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	return health
}
