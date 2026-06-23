//go:build trivylive

package trivy

import (
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/provider"
)

// TestLiveScan exercises the provider against a real Trivy server. Run with:
//
//	go test -tags trivylive -run TestLiveScan ./internal/provider/trivy/...
//
// Requires a Trivy server reachable at TRIVY_URL (default http://localhost:4954).
func TestLiveScan(t *testing.T) {
	baseURL := os.Getenv("TRIVY_URL")
	if baseURL == "" {
		baseURL = "http://localhost:4954"
	}
	p := New(baseURL, zerolog.Nop())
	results, err := p.QueryPackages(context.Background(), []provider.PackageQuery{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"},
	})
	if err != nil {
		t.Fatalf("live scan: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one vulnerability for lodash 4.17.15")
	}
	for _, r := range results {
		t.Logf("found %s severity=%v ranges=%+v", r.ProviderID, r.Severity, r.AffectedRanges)
	}
}
