package server

import (
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

// scannerCatalogDistribution is one artifact with where this installation
// fetches it from. Credentials never appear: configured URLs are validated
// to carry none.
type scannerCatalogDistribution struct {
	scancatalog.Distribution
	Location    *scancatalog.Location `json:"location,omitempty"`
	Unavailable string                `json:"unavailable,omitempty"`
}

type scannerCatalogEntry struct {
	scancatalog.Scanner
	Distributions []scannerCatalogDistribution `json:"distributions"`
}

type scannerCatalogResponse struct {
	Revision string                `json:"revision"`
	Mode     string                `json:"mode"`
	Scanners []scannerCatalogEntry `json:"scanners"`
	Rulesets []scancatalog.Ruleset `json:"rulesets"`
	// Bundle: the imported offline bundle, in offline mode only.
	Bundle *offlineBundleStatus `json:"bundle,omitempty"`
}

// @Summary      Bundled scanner catalog
// @Description  The scanners hibou supports in CI (ADR-035): capabilities per language with their evidence, pinned artifacts with sha256, and where this installation fetches each one (approved location, mirror, offline bundle or upstream) under its scanner_distribution policy.
// @Tags         scanners
// @Produce      json
// @Success      200  {object}  api.Response{data=server.scannerCatalogResponse}
// @Security     BearerAuth
// @Router       /scanner-catalog [get]
func (s *Server) handleGetScannerCatalog(w http.ResponseWriter, r *http.Request) {
	if s.scanCatalog == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "scanner catalog unavailable")
		return
	}
	cfg := s.cfg.ScannerDistribution.Normalize()
	response := scannerCatalogResponse{
		Revision: s.scanCatalog.Revision,
		Mode:     cfg.Mode,
		Scanners: make([]scannerCatalogEntry, 0, len(s.scanCatalog.Scanners)),
		Rulesets: s.scanCatalog.Rulesets,
		Bundle:   s.offlineBundle(),
	}
	for i := range s.scanCatalog.Scanners {
		scanner := &s.scanCatalog.Scanners[i]
		entry := scannerCatalogEntry{Scanner: *scanner, Distributions: make([]scannerCatalogDistribution, 0, len(scanner.Distributions))}
		for j := range scanner.Distributions {
			distribution := scannerCatalogDistribution{Distribution: scanner.Distributions[j]}
			location, err := cfg.Resolve(scanner, &scanner.Distributions[j])
			if err != nil {
				distribution.Unavailable = err.Error()
			} else {
				distribution.Location = &location
			}
			entry.Distributions = append(entry.Distributions, distribution)
		}
		response.Scanners = append(response.Scanners, entry)
	}
	api.JSON(w, http.StatusOK, response)
}
