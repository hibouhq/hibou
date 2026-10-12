package server

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hibouhq/hibou/internal/scanbundle"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

// offlineBundleStatus is what an offline installation runs scanners from
// (ADR-035 "Offline distribution"): when the bundle was exported and for
// which catalog. Its age is judged against the org freshness policy, so a
// stale bundle shows even though the scanners start fine.
type offlineBundleStatus struct {
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	CatalogRevision string     `json:"catalog_revision,omitempty"`
	// MatchesCatalog: exported for the catalog this server pins. After an
	// upgrade a mismatched bundle lacks the newly pinned artifacts.
	MatchesCatalog bool   `json:"matches_catalog"`
	Error          string `json:"error,omitempty"`
}

// bundleManifestCache keeps the parsed manifest until the file changes.
type bundleManifestCache struct {
	mu      sync.Mutex
	path    string
	modTime time.Time
	status  *offlineBundleStatus
}

// offlineBundle reports the imported bundle in offline mode, nil otherwise.
func (s *Server) offlineBundle() *offlineBundleStatus {
	cfg := s.cfg.ScannerDistribution.Normalize()
	if cfg.Mode != scancatalog.ModeOffline || cfg.BundleDir == "" {
		return nil
	}
	path := filepath.Join(cfg.BundleDir, scanbundle.ManifestName)
	info, err := os.Stat(path)
	if err != nil {
		return &offlineBundleStatus{Error: "no imported bundle manifest: run hibou scanners bundle import"}
	}
	cache := &s.bundleManifest
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.status != nil && cache.path == path && cache.modTime.Equal(info.ModTime()) {
		return cache.status
	}
	status := &offlineBundleStatus{}
	if manifest, err := scanbundle.ReadManifest(cfg.BundleDir); err != nil {
		status.Error = err.Error()
	} else {
		created := manifest.CreatedAt
		status.CreatedAt = &created
		status.CatalogRevision = manifest.CatalogRevision
		status.MatchesCatalog = s.scanCatalog != nil && manifest.CatalogRevision == s.scanCatalog.Revision
	}
	cache.path, cache.modTime, cache.status = path, info.ModTime(), status
	return status
}

// offlineBundleCreatedAt is the bundle's export time for coverage, nil when
// not offline or unknown.
func (s *Server) offlineBundleCreatedAt() *time.Time {
	if status := s.offlineBundle(); status != nil {
		return status.CreatedAt
	}
	return nil
}
