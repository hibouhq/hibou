package store

import (
	"database/sql"
	"net/url"
	"os"
	"testing"
)

func TestNewAppliesTCPDeadClientDetectionDefaults(t *testing.T) {
	db := openPoolTestDB(t, poolTestDatabaseURL())
	var tcp bool
	if err := db.QueryRow(`SELECT inet_client_addr() IS NOT NULL`).Scan(&tcp); err != nil {
		t.Fatal(err)
	}
	if !tcp {
		t.Skip("TCP keepalive settings require a TCP database connection")
	}
	for setting, want := range map[string]string{
		"tcp_keepalives_idle": "30", "tcp_keepalives_interval": "10",
		"tcp_keepalives_count": "3", "tcp_user_timeout": "60000",
	} {
		var got string
		if err := db.QueryRow(`SELECT setting FROM pg_settings WHERE name=$1`, setting).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s=%q want %q", setting, got, want)
		}
	}
}

func TestNewPreservesExplicitTCPSettings(t *testing.T) {
	for _, options := range []bool{false, true} {
		t.Run(map[bool]string{false: "startup parameters", true: "options"}[options], func(t *testing.T) {
			databaseURL, err := url.Parse(poolTestDatabaseURL())
			if err != nil {
				t.Fatal(err)
			}
			query := databaseURL.Query()
			if options {
				query.Set("options", "-c tcp_keepalives_idle=90 -c tcp_keepalives_interval=20 -c tcp_keepalives_count=5 -c tcp_user_timeout=120000")
			} else {
				query.Set("tcp_keepalives_idle", "90")
				query.Set("tcp_keepalives_interval", "20")
				query.Set("tcp_keepalives_count", "5")
				query.Set("tcp_user_timeout", "120000")
			}
			databaseURL.RawQuery = query.Encode()
			db := openPoolTestDB(t, databaseURL.String())
			var tcp bool
			if err := db.QueryRow(`SELECT inet_client_addr() IS NOT NULL`).Scan(&tcp); err != nil {
				t.Fatal(err)
			}
			if !tcp {
				t.Skip("TCP keepalive settings require a TCP database connection")
			}
			for setting, want := range map[string]string{
				"tcp_keepalives_idle": "90", "tcp_keepalives_interval": "20",
				"tcp_keepalives_count": "5", "tcp_user_timeout": "120000",
			} {
				var got string
				if err := db.QueryRow(`SELECT setting FROM pg_settings WHERE name=$1`, setting).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Errorf("%s=%q want %q", setting, got, want)
				}
			}
		})
	}
}

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
