package callgraph

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// Live checks against the sample project — skipped when the fixture or the
// toolchain is absent (CI has no rust/sample checkout for this repo's tests).
func TestScanRustCrateUsageLive(t *testing.T) {
	const fixture = "../../hibou-sample-project/rust"
	if _, err := os.Stat(fixture); err != nil {
		t.Skip("sample project not checked out")
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not on PATH")
	}

	usage, err := ScanRustCrateUsage(context.Background(), fixture)
	if err != nil {
		t.Fatalf("ScanRustCrateUsage: %v", err)
	}
	referenced := map[string]bool{}
	for _, crate := range usage.Referenced {
		referenced[crate] = true
	}
	present := map[string]bool{}
	for _, crate := range usage.Present {
		present[crate] = true
	}
	if !referenced["time"] {
		t.Fatalf("time must be referenced (fixture contract), got %v", usage.Referenced)
	}
	if !present["arrayvec"] || referenced["arrayvec"] {
		t.Fatalf("arrayvec must be present-but-unreferenced (fixture contract), got referenced=%v present=%v", usage.Referenced, usage.Present)
	}
}

func TestScanJavaClassReferencesLive(t *testing.T) {
	const classes = "/tmp/jc"
	if _, err := os.Stat(classes + "/com/hibou/sample/Reachability.class"); err != nil {
		t.Skip("compiled sample class not present")
	}
	packages, err := ScanJavaClassReferences(classes)
	if err != nil {
		t.Fatalf("ScanJavaClassReferences: %v", err)
	}
	found := false
	for _, pkg := range packages {
		if pkg == "org.apache.logging.log4j" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected org.apache.logging.log4j among referenced packages, got %v", packages)
	}
}

func TestGoReachableSymbolsLive(t *testing.T) {
	const fixture = "../../hibou-sample-project/go"
	if _, err := os.Stat(fixture); err != nil {
		t.Skip("sample project not checked out")
	}
	symbols, err := GoReachableSymbols(context.Background(), fixture)
	if err != nil {
		t.Fatalf("GoReachableSymbols: %v", err)
	}
	set := map[string]bool{}
	for _, symbol := range symbols {
		set[symbol] = true
	}
	// Fixture contract (go/reachability.go): yaml.Unmarshal is called,
	// jwt-go's vulnerable audience path is not.
	if !set["gopkg.in/yaml.v2.Unmarshal"] {
		t.Fatalf("yaml.Unmarshal must be reachable, got %d symbols (sample: %v)", len(symbols), symbols[:min(8, len(symbols))])
	}
	if set["github.com/dgrijalva/jwt-go.MapClaims.VerifyAudience"] {
		t.Fatalf("jwt-go audience path must NOT be reachable (fixture contract)")
	}
}
