package storageusage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/store"
)

// Runs the catalog queries against a real Postgres: sqlmock cannot tell
// whether pg_partition_tree folding or the casts are valid SQL.
func TestCollectAgainstPostgres(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://hibou:hibou@localhost:5432/hibou?sslmode=disable"
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	ctx := context.Background()

	pg := CollectPostgres(ctx, db, time.Now)
	if !pg.OK() {
		t.Fatalf("postgres sample failed: %s", pg.Error)
	}
	if pg.DatabaseBytes <= 0 || pg.ConnectionsUsed < 1 || pg.ConnectionsMax < pg.ConnectionsUsed || pg.XIDAge <= 0 {
		t.Fatalf("implausible postgres sample: %+v", pg)
	}
	if len(pg.Tables) == 0 || len(pg.Tables) > MaxTables {
		t.Fatalf("tables = %d, want 1..%d", len(pg.Tables), MaxTables)
	}
	seen := map[string]bool{}
	for i, tbl := range pg.Tables {
		if i > 0 {
			prev := pg.Tables[i-1]
			if prev.TableBytes+prev.IndexBytes < tbl.TableBytes+tbl.IndexBytes {
				t.Fatalf("tables not sorted by size: %s before %s", prev.Name, tbl.Name)
			}
		}
		if seen[tbl.Name] {
			t.Fatalf("table %q reported twice", tbl.Name)
		}
		seen[tbl.Name] = true
	}
	// audit_logs is partitioned by month: one root series, no partitions.
	if !seen["audit_logs"] {
		t.Error("partitioned audit_logs missing from table usage")
	}
	for name := range seen {
		if len(name) > len("audit_logs_") && name[:len("audit_logs_")] == "audit_logs_" {
			t.Errorf("partition %q leaked as its own series", name)
		}
	}

	ledger := CollectLedger(ctx, db, time.Now)
	if !ledger.OK() {
		t.Fatalf("ledger sample failed: %s", ledger.Error)
	}
}
