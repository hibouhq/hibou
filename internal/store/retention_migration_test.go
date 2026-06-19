package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

func TestRetentionStateBackfillSkipsArchivedAndPurgedSnapshots(t *testing.T) {
	db := newIsolatedRetentionMigrationTestDB(t)
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := migrateStoreTestDBToVersion(db, 10); err != nil {
		t.Fatalf("migrateStoreTestDBToVersion(10) returned error: %v", err)
	}

	ctx := context.Background()
	fixture := seedPreRetentionStateFixture(t, ctx, db)

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() after pre-00011 seed returned error: %v", err)
	}

	queries := NewQueries(db)
	activeSnapshot, err := queries.GetSnapshotByID(ctx, fixture.activeSnapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(active) error = %v", err)
	}
	if activeSnapshot == nil || activeSnapshot.ArtifactBytes != 100 {
		t.Fatalf("active snapshot artifact_bytes = %#v, want 100", activeSnapshot)
	}
	archivedSnapshot, err := queries.GetSnapshotByID(ctx, fixture.archivedSnapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(archived) error = %v", err)
	}
	if archivedSnapshot == nil || archivedSnapshot.ArtifactBytes != 0 {
		t.Fatalf("archived snapshot artifact_bytes = %#v, want 0", archivedSnapshot)
	}
	purgedSnapshot, err := queries.GetSnapshotByID(ctx, fixture.purgedSnapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(purged) error = %v", err)
	}
	if purgedSnapshot == nil || purgedSnapshot.ArtifactBytes != 0 {
		t.Fatalf("purged snapshot artifact_bytes = %#v, want 0", purgedSnapshot)
	}

	storedRepo, err := queries.GetRepositoryByID(ctx, fixture.repoID)
	if err != nil {
		t.Fatalf("GetRepositoryByID() error = %v", err)
	}
	if storedRepo == nil || storedRepo.RetentionArtifactBytes != 100 {
		t.Fatalf("repository retention_artifact_bytes = %#v, want 100", storedRepo)
	}
}

type retentionMigrationFixture struct {
	repoID             uuid.UUID
	activeSnapshotID   uuid.UUID
	archivedSnapshotID uuid.UUID
	purgedSnapshotID   uuid.UUID
}

func seedPreRetentionStateFixture(t *testing.T, ctx context.Context, db *sql.DB) retentionMigrationFixture {
	t.Helper()

	orgID := uuid.New()
	repoID := uuid.New()
	refID := uuid.New()
	activeSnapshotID := uuid.New()
	archivedSnapshotID := uuid.New()
	purgedSnapshotID := uuid.New()

	orgName := uniqueStoreTestName(t, "org")
	repoName := uniqueStoreTestName(t, "repo")
	providerID := uniqueStoreTestName(t, "provider")
	commitSHA := uniqueStoreTestName(t, "commit")

	if _, err := db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug, display_name, provider)
		VALUES ($1, $2, $3, $4, 'github')
	`, orgID, orgName, orgName, "Retention Migration Org"); err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO repositories (id, org_id, name, slug, provider, provider_id, default_branch, sync_state)
		VALUES ($1, $2, $3, $4, 'github', $5, 'main', 'enrolled')
	`, repoID, orgID, repoName, repoName, providerID); err != nil {
		t.Fatalf("insert repository: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO refs (id, repo_id, name, ref_type, latest_commit_sha)
		VALUES ($1, $2, 'main', 'branch', $3)
	`, refID, repoID, commitSHA); err != nil {
		t.Fatalf("insert ref: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO snapshots (id, ref_id, commit_sha, status)
		VALUES
			($1, $4, $7, 'complete'),
			($2, $5, $8, 'archived'),
			($3, $6, $9, 'purged')
	`, activeSnapshotID, archivedSnapshotID, purgedSnapshotID, refID, refID, refID, commitSHA, uniqueStoreTestName(t, "archived"), uniqueStoreTestName(t, "purged")); err != nil {
		t.Fatalf("insert snapshots: %v", err)
	}

	insertArtifact := func(snapshotID uuid.UUID, size int64) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO snapshot_artifacts (snapshot_id, kind, object_key, size_bytes)
			VALUES ($1, 'sbom', $2, $3)
		`, snapshotID, "snapshots/"+snapshotID.String()+"/artifact", size); err != nil {
			t.Fatalf("insert snapshot_artifact for %s: %v", snapshotID, err)
		}
	}
	insertArtifact(activeSnapshotID, 100)
	insertArtifact(archivedSnapshotID, 250)
	insertArtifact(purgedSnapshotID, 400)

	return retentionMigrationFixture{
		repoID:             repoID,
		activeSnapshotID:   activeSnapshotID,
		archivedSnapshotID: archivedSnapshotID,
		purgedSnapshotID:   purgedSnapshotID,
	}
}

func newIsolatedRetentionMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()

	databaseURL := retentionMigrationTestDatabaseURL()
	adminDB := openRetentionMigrationTestDB(t, retentionMigrationAdminDatabaseURL(t, databaseURL), "retention migration admin")
	databaseName := retentionMigrationDatabaseName(t)

	if _, err := adminDB.Exec(fmt.Sprintf("CREATE DATABASE %s", pq.QuoteIdentifier(databaseName))); err != nil {
		_ = adminDB.Close()
		t.Fatalf("create retention migration database %q: %v", databaseName, err)
	}

	db := openRetentionMigrationTestDB(t, retentionMigrationDatabaseURL(t, databaseURL, databaseName), "retention migration isolated database")
	t.Cleanup(func() {
		_ = db.Close()
		if _, err := adminDB.Exec(`
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = $1 AND pid <> pg_backend_pid()
		`, databaseName); err != nil {
			t.Fatalf("terminate retention migration database connections %q: %v", databaseName, err)
		}
		if _, err := adminDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", pq.QuoteIdentifier(databaseName))); err != nil {
			t.Fatalf("drop retention migration database %q: %v", databaseName, err)
		}
		if err := adminDB.Close(); err != nil {
			t.Fatalf("close retention migration admin database %q: %v", databaseName, err)
		}
	})

	return db
}

func openRetentionMigrationTestDB(t *testing.T, databaseURL, description string) *sql.DB {
	t.Helper()

	var (
		db  *sql.DB
		err error
	)
	for range 10 {
		db, err = New(databaseURL)
		if err == nil {
			return db
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Skipf("database not available for %s: %v", description, err)
	return nil
}

func migrateStoreTestDBToVersion(db *sql.DB, version uint) error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("creating migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}

	if err := m.Migrate(version); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations to version %d: %w", version, err)
	}

	return nil
}

func retentionMigrationTestDatabaseURL() string {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		return testDatabaseURL
	}

	return databaseURL
}

func retentionMigrationAdminDatabaseURL(t *testing.T, databaseURL string) string {
	t.Helper()
	return retentionMigrationDatabaseURL(t, databaseURL, "postgres")
}

func retentionMigrationDatabaseURL(t *testing.T, databaseURL, databaseName string) string {
	t.Helper()

	parsedURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse database url %q: %v", databaseURL, err)
	}
	parsedURL.Path = "/" + databaseName
	return parsedURL.String()
}

func retentionMigrationDatabaseName(t *testing.T) string {
	t.Helper()

	baseName := normalizeStoreTestName(t.Name())
	baseName = strings.ReplaceAll(baseName, "-", "_")
	return "hibou_retention_" + baseName + "_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
}
