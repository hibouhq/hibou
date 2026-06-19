package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestUpsertRefStoresPRKindAndNumber(t *testing.T) {
	queries := newRefsTestQueries(t)
	ctx := context.Background()
	org, err := queries.CreateOrganization(ctx, uniqueStoreTestName(t, "org"), uniqueStoreTestName(t, "org"), "Refs Org", "github")
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	repo, err := queries.CreateRepository(ctx, org.ID, nil, uniqueStoreTestName(t, "repo"), uniqueStoreTestName(t, "repo"), "github", uniqueStoreTestName(t, "provider"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository() error = %v", err)
	}
	commitSHA := uniqueStoreTestName(t, "commit")
	number := "7"

	ref, err := queries.UpsertRef(ctx, repo.ID, "refs/pull/7/merge", RefTypePullRequest, UpsertRefOptions{
		LatestCommitSHA: &commitSHA,
		PRRefKind:       "merge",
		PRNumber:        &number,
		PRTitle:         "Docs update",
	})
	if err != nil {
		t.Fatalf("UpsertRef() insert error = %v", err)
	}
	if ref.PrRefKind != "merge" {
		t.Fatalf("inserted ref kind = %q, want merge", ref.PrRefKind)
	}
	if ref.PrNumber == nil || *ref.PrNumber != "7" {
		t.Fatalf("inserted ref number = %v, want 7", ref.PrNumber)
	}

	ref, err = queries.UpsertRef(ctx, repo.ID, "refs/pull/7/merge", RefTypePullRequest, UpsertRefOptions{
		PRRefKind: "merge",
		PRTitle:   "Docs update",
	})
	if err != nil {
		t.Fatalf("UpsertRef() update error = %v", err)
	}
	if ref.PrRefKind != "merge" {
		t.Fatalf("updated ref kind = %q, want merge", ref.PrRefKind)
	}
	if ref.PrNumber == nil || *ref.PrNumber != "7" {
		t.Fatalf("updated ref number = %v, want preserved 7", ref.PrNumber)
	}
}

func newRefsTestQueries(t *testing.T) *Queries {
	t.Helper()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}

	var (
		db  *sql.DB
		err error
	)
	for range 10 {
		db, err = New(databaseURL)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("database not available for refs test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	return NewQueries(db)
}
