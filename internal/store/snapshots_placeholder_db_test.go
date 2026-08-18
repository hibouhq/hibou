package store

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
)

func newSnapshotTestDB(t *testing.T) (*Queries, *sql.DB) {
	t.Helper()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"
	}
	db, err := New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Skipf("database not available: %v", err)
	}
	return NewQueries(db), db
}

func createSnapshotTestRef(t *testing.T, queries *Queries) uuid.UUID {
	t.Helper()
	ctx := context.Background()

	org, err := queries.CreateOrganization(ctx, "ph-org-"+uuid.NewString()[:8], "ph-org-"+uuid.NewString()[:8], "Placeholder Org", "github")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	repo, err := queries.CreateRepository(ctx, org.ID, nil, "ph-repo", "ph-repo-"+uuid.NewString()[:8], "github", "acme/ph-"+uuid.NewString()[:8], "main", "synced")
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}
	ref, err := queries.UpsertRef(ctx, repo.ID, "refs/pull/7", "pull_request", UpsertRefOptions{})
	if err != nil {
		t.Fatalf("create ref: %v", err)
	}
	return ref.ID
}

func TestCreatePlaceholderSnapshotOnlyWhenAbsent(t *testing.T) {
	queries, _ := newSnapshotTestDB(t)
	ctx := context.Background()
	refID := createSnapshotTestRef(t, queries)

	created, err := queries.CreatePlaceholderSnapshot(ctx, refID, "headsha1111")
	if err != nil {
		t.Fatalf("create placeholder: %v", err)
	}
	if created == nil || created.Status != SnapshotStatusPending || created.RunID != nil {
		t.Fatalf("placeholder = %+v, want pending with no run_id", created)
	}

	// Second webhook delivery for the same head: no duplicate.
	again, err := queries.CreatePlaceholderSnapshot(ctx, refID, "headsha1111")
	if err != nil {
		t.Fatalf("re-create placeholder: %v", err)
	}
	if again != nil {
		t.Fatalf("expected nil (already exists), got %+v", again)
	}
}

func TestUpsertSnapshotForBuildAdoptsPlaceholder(t *testing.T) {
	queries, _ := newSnapshotTestDB(t)
	ctx := context.Background()
	refID := createSnapshotTestRef(t, queries)

	placeholder, err := queries.CreatePlaceholderSnapshot(ctx, refID, "headsha2222")
	if err != nil || placeholder == nil {
		t.Fatalf("create placeholder: %v %+v", err, placeholder)
	}

	runID := "run-42"
	buildURL := "https://ci.example/run/42"
	adopted, err := queries.UpsertSnapshotForBuild(ctx, refID, "headsha2222", SnapshotStatusPending, SnapshotBuildMeta{
		RunID:    &runID,
		BuildURL: &buildURL,
	})
	if err != nil {
		t.Fatalf("upsert for build: %v", err)
	}
	if adopted.ID != placeholder.ID {
		t.Fatalf("upload must adopt the placeholder row, got a new snapshot %s (placeholder %s)", adopted.ID, placeholder.ID)
	}
	if adopted.RunID == nil || *adopted.RunID != runID {
		t.Fatalf("adopted run_id = %v, want %q", adopted.RunID, runID)
	}

	// A retry of the SAME build hits the normal upsert conflict path, still one row.
	retried, err := queries.UpsertSnapshotForBuild(ctx, refID, "headsha2222", SnapshotStatusPending, SnapshotBuildMeta{RunID: &runID})
	if err != nil {
		t.Fatalf("retry upsert: %v", err)
	}
	if retried.ID != placeholder.ID {
		t.Fatalf("retry created a duplicate snapshot %s", retried.ID)
	}
}
