package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUpsertForgeRepositoryPreservesArchivedState(t *testing.T) {
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
		t.Skipf("database not available for forge repository test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	queries := NewQueries(db)
	ctx := context.Background()
	account := "archived-preserved-" + normalizeStoreTestName(t.Name())
	fullName := account + "/api"
	providerRepoID := "repo-" + normalizeStoreTestName(t.Name())

	if _, err := queries.UpsertForgeRepository(ctx, ForgeRepository{
		Provider:       "github",
		ProviderRepoID: &providerRepoID,
		AccountLogin:   account,
		Owner:          account,
		Name:           "api",
		FullName:       fullName,
		Private:        true,
		DefaultBranch:  "main",
		HTMLURL:        "https://github.com/" + fullName,
	}); err != nil {
		t.Fatalf("initial UpsertForgeRepository() error = %v", err)
	}
	if _, err := queries.SetForgeRepositoryArchived(ctx, "github", fullName, true); err != nil {
		t.Fatalf("SetForgeRepositoryArchived() error = %v", err)
	}

	updated, err := queries.UpsertForgeRepository(ctx, ForgeRepository{
		Provider:       "github",
		ProviderRepoID: &providerRepoID,
		AccountLogin:   account,
		Owner:          account,
		Name:           "api",
		FullName:       fullName,
		Private:        true,
		Archived:       false,
	})
	if err != nil {
		t.Fatalf("slim UpsertForgeRepository() error = %v", err)
	}
	if updated == nil || updated.Repository == nil {
		t.Fatalf("expected upsert result repository, got %#v", updated)
	}
	if !updated.Repository.Archived {
		t.Fatalf("expected archived state preserved on slim upsert, got %#v", updated)
	}
	if !updated.Repository.Private {
		t.Fatalf("expected private state preserved from slim upsert payload, got %#v", updated)
	}
	if updated.Repository.DefaultBranch != "main" {
		t.Fatalf("expected default branch preserved on slim upsert, got %#v", updated)
	}
	if updated.Repository.HTMLURL != "https://github.com/"+fullName {
		t.Fatalf("expected html_url preserved on slim upsert, got %#v", updated)
	}
	stored, err := queries.ListForgeRepositoriesByAccount(ctx, "github", account)
	if err != nil {
		t.Fatalf("ListForgeRepositoriesByAccount() error = %v", err)
	}
	if len(stored) != 1 || !stored[0].Archived {
		t.Fatalf("expected archived repo to remain active and archived, got %#v", stored)
	}
}

func TestForgeRepositoryTransitionFlagsAndChangeRows(t *testing.T) {
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
		t.Skipf("database not available for forge repository test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	queries := NewQueries(db)
	ctx := context.Background()
	testName := normalizeStoreTestName(t.Name())
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "-")
	account := "transitions-" + testName + "-" + suffix
	fullName := account + "/api"
	providerRepoID := "repo-" + testName
	installationID := time.Now().UTC().UnixNano()

	first, err := queries.UpsertForgeRepository(ctx, ForgeRepository{
		Provider:       "github",
		InstallationID: &installationID,
		ProviderRepoID: &providerRepoID,
		AccountLogin:   account,
		Owner:          account,
		Name:           "api",
		FullName:       fullName,
		Private:        true,
		DefaultBranch:  "main",
		HTMLURL:        "https://github.com/" + fullName,
	})
	if err != nil {
		t.Fatalf("first UpsertForgeRepository() error = %v", err)
	}
	if first == nil || first.Repository == nil {
		t.Fatalf("expected first upsert result repository, got %#v", first)
	}
	if !first.Inserted || first.PreviouslyRemoved {
		t.Fatalf("first upsert flags = inserted:%t previously_removed:%t, want true/false", first.Inserted, first.PreviouslyRemoved)
	}

	second, err := queries.UpsertForgeRepository(ctx, ForgeRepository{
		Provider:       "github",
		InstallationID: &installationID,
		ProviderRepoID: &providerRepoID,
		AccountLogin:   account,
		Owner:          account,
		Name:           "api",
		FullName:       fullName,
		Private:        true,
	})
	if err != nil {
		t.Fatalf("second UpsertForgeRepository() error = %v", err)
	}
	if second == nil || second.Repository == nil {
		t.Fatalf("expected second upsert result repository, got %#v", second)
	}
	if second.Inserted || second.PreviouslyRemoved {
		t.Fatalf("second upsert flags = inserted:%t previously_removed:%t, want false/false", second.Inserted, second.PreviouslyRemoved)
	}

	deleted, err := queries.SoftDeleteForgeRepository(ctx, "github", fullName)
	if err != nil {
		t.Fatalf("first SoftDeleteForgeRepository() error = %v", err)
	}
	if deleted == nil || deleted.FullName != fullName {
		t.Fatalf("expected first soft delete change row for %s, got %#v", fullName, deleted)
	}
	deletedAgain, err := queries.SoftDeleteForgeRepository(ctx, "github", fullName)
	if err != nil {
		t.Fatalf("second SoftDeleteForgeRepository() error = %v", err)
	}
	if deletedAgain != nil {
		t.Fatalf("expected second soft delete no change row, got %#v", deletedAgain)
	}

	third, err := queries.UpsertForgeRepository(ctx, ForgeRepository{
		Provider:       "github",
		InstallationID: &installationID,
		ProviderRepoID: &providerRepoID,
		AccountLogin:   account,
		Owner:          account,
		Name:           "api",
		FullName:       fullName,
		Private:        true,
	})
	if err != nil {
		t.Fatalf("third UpsertForgeRepository() error = %v", err)
	}
	if third == nil || third.Repository == nil {
		t.Fatalf("expected third upsert result repository, got %#v", third)
	}
	if third.Inserted || !third.PreviouslyRemoved {
		t.Fatalf("third upsert flags = inserted:%t previously_removed:%t, want false/true", third.Inserted, third.PreviouslyRemoved)
	}

	archived, err := queries.SetForgeRepositoryArchived(ctx, "github", fullName, true)
	if err != nil {
		t.Fatalf("SetForgeRepositoryArchived(true) error = %v", err)
	}
	if archived == nil || archived.FullName != fullName {
		t.Fatalf("expected archive change row for %s, got %#v", fullName, archived)
	}
	archivedAgain, err := queries.SetForgeRepositoryArchived(ctx, "github", fullName, true)
	if err != nil {
		t.Fatalf("SetForgeRepositoryArchived(true again) error = %v", err)
	}
	if archivedAgain != nil {
		t.Fatalf("expected same-value archive no change row, got %#v", archivedAgain)
	}

	removedByInstallation, err := queries.MarkInstallationRepositoriesRemoved(ctx, "github", installationID)
	if err != nil {
		t.Fatalf("first MarkInstallationRepositoriesRemoved() error = %v", err)
	}
	if len(removedByInstallation) != 1 || removedByInstallation[0].FullName != fullName {
		t.Fatalf("expected one installation removal change row for %s, got %#v", fullName, removedByInstallation)
	}
	removedByInstallationAgain, err := queries.MarkInstallationRepositoriesRemoved(ctx, "github", installationID)
	if err != nil {
		t.Fatalf("second MarkInstallationRepositoriesRemoved() error = %v", err)
	}
	if len(removedByInstallationAgain) != 0 {
		t.Fatalf("expected second installation removal no change rows, got %#v", removedByInstallationAgain)
	}
}

func normalizeStoreTestName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "/", "-")
	return strings.ReplaceAll(name, "_", "-")
}
