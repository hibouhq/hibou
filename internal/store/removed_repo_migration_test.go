package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

func TestRemovedRepositoryNameMigration(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Errorf("rollback migration test: %v", err)
		}
	}()
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE incidents (id uuid PRIMARY KEY, title text) ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := tx.ExecContext(ctx, `INSERT INTO incidents VALUES ($1,'Fixture incident')`, id); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"up", "down", "up"} {
		script, err := migrationsFS.ReadFile("migrations/00084_incidents_keep_removed_repo_name." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			t.Fatalf("%s migration: %v", direction, err)
		}
	}
	var title string
	var removedName sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT title,removed_repo_name FROM incidents WHERE id=$1`, id).Scan(&title, &removedName); err != nil {
		t.Fatal(err)
	}
	if title != "Fixture incident" || removedName.Valid {
		t.Fatalf("existing incident changed: title=%q removed=%+v", title, removedName)
	}
}
