package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/scanbundle"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

func TestOfflineBundleStatus(t *testing.T) {
	dir := t.TempDir()
	srv := &Server{scanCatalog: &scancatalog.Catalog{Revision: "2026-10-01"}}
	if srv.offlineBundle() != nil {
		t.Fatal("upstream mode has no bundle")
	}
	srv.cfg = config.Config{ScannerDistribution: scancatalog.DistributionConfig{Mode: scancatalog.ModeOffline, BundleDir: dir}}
	if status := srv.offlineBundle(); status == nil || status.Error == "" {
		t.Fatalf("missing manifest = %+v", status)
	}
	write := func(body string, at time.Time) {
		path := filepath.Join(dir, scanbundle.ManifestName)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"schema_version":1,"catalog_revision":"2026-09-01","created_at":"2026-09-02T00:00:00Z"}`, time.Now().Add(-time.Hour))
	status := srv.offlineBundle()
	if status.CreatedAt == nil || !status.CreatedAt.Equal(time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)) || status.MatchesCatalog {
		t.Fatalf("older-catalog bundle = %+v", status)
	}
	// A re-import (new mtime) is picked up without a restart.
	write(`{"schema_version":1,"catalog_revision":"2026-10-01","created_at":"2026-10-05T00:00:00Z"}`, time.Now())
	if status := srv.offlineBundle(); !status.MatchesCatalog || srv.offlineBundleCreatedAt().Day() != 5 {
		t.Fatalf("re-imported bundle = %+v", status)
	}
}
