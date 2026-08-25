package osv

import (
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog"
)

// Opt-in: hits api.osv.dev. Proves alias-following against the live shape, which
// is the part a fixture cannot keep honest.
func TestPackagesForVulnLive(t *testing.T) {
	if os.Getenv("HIBOU_OSV_LIVE") == "" {
		t.Skip("set HIBOU_OSV_LIVE=1 to run")
	}
	provider := New("", zerolog.Nop())
	for _, id := range []string{"CVE-2021-44228", "CVE-2026-59084"} {
		coordinates, err := provider.PackagesForVuln(context.Background(), id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		t.Logf("%s -> %d coordinates %v", id, len(coordinates), coordinates)
	}
}
