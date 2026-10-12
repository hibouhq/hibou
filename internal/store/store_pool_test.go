package store

import (
	"database/sql"
	"os"
	"testing"
)

func openPoolTestDB(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	db, err := New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func poolTestDatabaseURL() string {
	if databaseURL := os.Getenv("HIBOU_DATABASE_URL"); databaseURL != "" {
		return databaseURL
	}
	return testDatabaseURL
}

func showSetting(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var value string
	if err := db.QueryRow(`SELECT current_setting($1)`, name).Scan(&value); err != nil {
		t.Fatalf("current_setting(%s): %v", name, err)
	}
	return value
}

func TestNewAppliesSessionTimeoutsAndPoolLimits(t *testing.T) {
	db := openPoolTestDB(t, poolTestDatabaseURL())
	if got := showSetting(t, db, "statement_timeout"); got != "1min" {
		t.Fatalf("statement_timeout = %q, want 1min", got)
	}
	if got := showSetting(t, db, "idle_in_transaction_session_timeout"); got != "1min" {
		t.Fatalf("idle_in_transaction_session_timeout = %q, want 1min", got)
	}
	if got := db.Stats().MaxOpenConnections; got != DefaultPoolConfig.MaxOpenConns {
		t.Fatalf("MaxOpenConnections = %d, want %d", got, DefaultPoolConfig.MaxOpenConns)
	}
}

func TestNewKeepsTimeoutsSetInTheURL(t *testing.T) {
	db := openPoolTestDB(t, poolTestDatabaseURL()+"&statement_timeout=0")
	if got := showSetting(t, db, "statement_timeout"); got != "0" {
		t.Fatalf("statement_timeout = %q, want the URL's 0", got)
	}
}

func TestMigrateRestoresStatementTimeoutOnPooledConnection(t *testing.T) {
	db := openPoolTestDB(t, poolTestDatabaseURL())
	// One connection: whatever Migrate used is what the next query gets.
	db.SetMaxOpenConns(1)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if got := showSetting(t, db, "statement_timeout"); got != "1min" {
		t.Fatalf("statement_timeout after Migrate = %q, want 1min", got)
	}
}
