package storageusage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hibouhq/hibou/internal/objstore"
)

func fixedClock() func() time.Time {
	t := time.Unix(1_760_000_000, 0)
	return func() time.Time { return t }
}

func TestExporterRendersSample(t *testing.T) {
	t.Parallel()

	ratio := 0.99
	capacity, free := int64(1000), int64(400)
	e := &Exporter{}
	e.Publish(&Sample{
		Postgres: &Postgres{
			Section:         Section{CollectedAt: time.Unix(100, 0), DurationSeconds: 0.5},
			DatabaseBytes:   4096,
			Tables:          []TableUsage{{Name: "findings", TableBytes: 3000, IndexBytes: 1000, LiveRows: 10, DeadRows: 2}},
			ConnectionsUsed: 7,
			ConnectionsMax:  100,
			XIDAge:          1234,
			CacheHitRatio:   &ratio,
		},
		Ledger: &Ledger{
			Section: Section{CollectedAt: time.Unix(100, 0)},
			Kinds:   []KindUsage{{Kind: "sbom", Objects: 3, Bytes: 300}},
		},
		Backend: &Backend{
			Section:             Section{CollectedAt: time.Unix(50, 0)},
			Objects:             4,
			Bytes:               350,
			VolumeCapacityBytes: &capacity,
			VolumeFreeBytes:     &free,
		},
	})

	out := scrape(t, e)
	for _, line := range []string{
		`hibou_artifact_backend_bytes 350`,
		`hibou_artifact_backend_scan_truncated 0`,
		`hibou_artifact_ledger_bytes{kind="sbom"} 300`,
		`hibou_artifact_volume_free_bytes 400`,
		`hibou_db_cache_hit_ratio 0.99`,
		`hibou_db_size_bytes 4096`,
		`hibou_db_table_rows{state="dead",table="findings"} 2`,
		`hibou_db_table_size_bytes{part="index",table="findings"} 1000`,
		`hibou_db_table_size_bytes{part="table",table="findings"} 3000`,
		`hibou_storage_sample_success{source="backend"} 1`,
		`hibou_storage_sample_success{source="postgres"} 1`,
		`hibou_storage_sample_timestamp_seconds{source="backend"} 50`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("scrape missing %q", line)
		}
	}
	// Absent values stay absent rather than exporting a fake zero.
	if strings.Contains(out, "hibou_db_oldest_transaction_seconds ") {
		t.Error("oldest transaction exported although unknown")
	}
}

// scrape renders e through a pedantic registry, which also validates the
// descriptors against what Collect emits.
func scrape(t *testing.T, e *Exporter) string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(e); err != nil {
		t.Fatalf("register: %v", err)
	}
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestExporterFailedSourceExportsOnlyStatus(t *testing.T) {
	t.Parallel()

	e := &Exporter{}
	e.Publish(&Sample{Postgres: &Postgres{
		Section:       Section{CollectedAt: time.Unix(100, 0), Error: "boom"},
		DatabaseBytes: 999, // partial data from before the failure
	}})

	out := scrape(t, e)
	if strings.Contains(out, "hibou_db_size_bytes ") {
		t.Error("failed source exported its partial data")
	}
	if !strings.Contains(out, `hibou_storage_sample_success{source="postgres"} 0`+"\n") {
		t.Errorf("missing failure status in:\n%s", out)
	}
}

func TestExporterEmptyBeforeFirstSample(t *testing.T) {
	t.Parallel()

	if out := scrape(t, &Exporter{}); strings.Contains(out, "hibou_") {
		t.Fatalf("exported series before any sample:\n%s", out)
	}
}

func TestCollectLedgerRunsReadOnlyWithTimeout(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL statement_timeout = '10s'`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM snapshot_artifacts`).WithArgs(maxKinds).WillReturnRows(
		sqlmock.NewRows([]string{"kind", "count", "sum"}).AddRow("sarif", 2, 200).AddRow("sbom", 1, 50))
	mock.ExpectRollback()

	got := CollectLedger(context.Background(), db, fixedClock())
	if !got.OK() {
		t.Fatalf("ledger error = %q", got.Error)
	}
	want := []KindUsage{{Kind: "sarif", Objects: 2, Bytes: 200}, {Kind: "sbom", Objects: 1, Bytes: 50}}
	if len(got.Kinds) != len(want) || got.Kinds[0] != want[0] || got.Kinds[1] != want[1] {
		t.Fatalf("kinds = %+v, want %+v", got.Kinds, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectPostgresRecordsFailure(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL statement_timeout`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`pg_database_size`).WillReturnError(errors.New("permission denied"))
	mock.ExpectRollback()

	got := CollectPostgres(context.Background(), db, fixedClock())
	if got.OK() || !strings.Contains(got.Error, "permission denied") {
		t.Fatalf("error = %q, want permission denied", got.Error)
	}
	if got.CollectedAt.IsZero() {
		t.Fatal("a failed section must keep its timestamp")
	}
}

type fakeInventory struct {
	inv objstore.Inventory
	err error
}

func (f fakeInventory) Inventory(context.Context, int64) (objstore.Inventory, error) {
	return f.inv, f.err
}

func TestCollectBackend(t *testing.T) {
	t.Parallel()

	got := CollectBackend(context.Background(), fakeInventory{inv: objstore.Inventory{
		Objects: 5, Bytes: 500, Truncated: true,
		Volume: &objstore.VolumeStats{CapacityBytes: 1000, FreeBytes: 10},
	}}, 5, fixedClock())
	if !got.OK() || got.Objects != 5 || got.Bytes != 500 || !got.Truncated || *got.VolumeFreeBytes != 10 {
		t.Fatalf("backend = %+v", got)
	}

	failed := CollectBackend(context.Background(), fakeInventory{err: errors.New("access denied")}, 5, fixedClock())
	if failed.OK() || failed.Objects != 0 {
		t.Fatalf("failed backend = %+v", failed)
	}
}
