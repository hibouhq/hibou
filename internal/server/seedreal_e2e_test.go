package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/cvetriage"
	"github.com/hibouhq/hibou/internal/store"
)

// Opt-in end-to-end: seeds the real corpus into the real database, the way a
// fresh instance does on its first sweep.
func TestSeedCVECorpusEndToEnd(t *testing.T) {
	if os.Getenv("HIBOU_SEED_E2E") == "" {
		t.Skip("set HIBOU_SEED_E2E=1 to run")
	}
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
		t.Fatalf("migrate: %v", err)
	}

	srv := &Server{db: db, queries: store.NewQueries(db), log: zerolog.New(os.Stdout)}
	sweeper := &cvetriage.Sweeper{Source: &cvefeed.GitSource{Dir: t.TempDir()}}

	start := time.Now()
	if err := srv.seedCVECorpusIfEmpty(context.Background(), sweeper); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Logf("first seed took %s", time.Since(start).Round(time.Second))

	// Second call must be a no-op: seeding once per instance, not once per pod.
	again := time.Now()
	if err := srv.seedCVECorpusIfEmpty(context.Background(), sweeper); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if elapsed := time.Since(again); elapsed > 5*time.Second {
		t.Errorf("second call took %s; it re-imported instead of noticing the anchor", elapsed)
	}
}
