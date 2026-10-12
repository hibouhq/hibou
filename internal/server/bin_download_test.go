package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The checksum is computed once per file version and follows a replaced
// binary (new size or mtime), so an upgrade never serves a stale digest.
func TestBinChecksumFollowsReplacedBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), binFilename("linux", "amd64"))
	want := func(content string) string {
		sum := sha256.Sum256([]byte(content))
		return hex.EncodeToString(sum[:])
	}
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sum, ok := binChecksum(path); !ok || sum != want("v1") {
		t.Fatalf("first checksum = %q, %v", sum, ok)
	}
	if err := os.WriteFile(path, []byte("v2-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if sum, ok := binChecksum(path); !ok || sum != want("v2-longer") {
		t.Fatalf("replaced binary checksum = %q, %v", sum, ok)
	}
	if _, ok := binChecksum(filepath.Join(filepath.Dir(path), "missing")); ok {
		t.Fatal("a missing binary has no checksum")
	}
}
