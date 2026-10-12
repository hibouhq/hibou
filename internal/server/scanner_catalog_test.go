package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

func TestScannerCatalogResolvesMirrorLocations(t *testing.T) {
	catalog, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{scanCatalog: catalog, cfg: config.Config{ScannerDistribution: scancatalog.DistributionConfig{
		Mode:          scancatalog.ModeMirror,
		MirrorBaseURL: "https://mirror.example.test/scanners",
	}}}
	recorder := httptest.NewRecorder()
	srv.handleGetScannerCatalog(recorder, httptest.NewRequest(http.MethodGet, "/scanner-catalog", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data scannerCatalogResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Mode != scancatalog.ModeMirror || len(envelope.Data.Scanners) != len(catalog.Scanners) {
		t.Fatalf("response = %+v", envelope.Data)
	}
	for _, scanner := range envelope.Data.Scanners {
		for _, distribution := range scanner.Distributions {
			switch distribution.Kind {
			case scancatalog.KindBinary:
				if distribution.Location == nil || distribution.Location.Source != "mirror" {
					t.Fatalf("%s binary must come from the mirror: %+v", scanner.ID, distribution)
				}
			case scancatalog.KindMaven:
				// No Maven mirror configured, and mirror mode never falls back.
				if distribution.Unavailable == "" {
					t.Fatalf("%s maven artifact must be unavailable: %+v", scanner.ID, distribution)
				}
			}
		}
	}
}
