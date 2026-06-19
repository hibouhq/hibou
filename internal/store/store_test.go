package store

import (
	"database/sql"
	"os"
	"testing"
	"time"
)

// testDatabaseURL targets a dedicated test database so integration tests never
// pollute the dev database (hibou). Override with HIBOU_DATABASE_URL.
const testDatabaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"

func TestMigrate(t *testing.T) {
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
		t.Skipf("database not available for migration test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate() returned error: %v", err)
	}

	var exists bool
	if err := db.QueryRow(`SELECT to_regclass('public.organizations') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("checking organizations table: %v", err)
	}
	if !exists {
		t.Fatal("expected organizations table to exist after migration")
	}

	if err := db.QueryRow(`SELECT to_regclass('public.casbin_rules') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("checking casbin_rules table: %v", err)
	}
	if !exists {
		t.Fatal("expected casbin_rules table to exist after migration")
	}
}
