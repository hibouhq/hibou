package scanbundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanrun"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testCatalog(base string) *scancatalog.Catalog {
	binary, jar := []byte("binary-linux-amd64"), []byte("plugin-jar")
	return &scancatalog.Catalog{SchemaVersion: 1, Revision: "test.1", Scanners: []scancatalog.Scanner{{
		ID: "tool", Name: "Tool", EngineVersion: "1.0", License: "MIT",
		Distributions: []scancatalog.Distribution{
			{Kind: "binary", OS: "linux", Arch: "amd64", Asset: "tool_linux_x86", URL: base + "/tool_linux_x86", SHA256: digest(binary)},
			{Kind: "maven", Coordinates: "org.example:plugin:1.0", URL: base + "/maven2/org/example/plugin/1.0/plugin-1.0.jar", SHA256: digest(jar)},
		},
	}}}
}

func TestExportThenImport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "tool_linux_x86"):
			_, _ = w.Write([]byte("binary-linux-amd64"))
		case strings.HasSuffix(r.URL.Path, ".jar"):
			_, _ = w.Write([]byte("plugin-jar"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	catalog := testCatalog(server.URL)
	out := t.TempDir()

	manifest, err := Export(context.Background(), catalog, ExportOptions{
		OutDir: out, Platforms: []string{"linux/amd64", "darwin/arm64"},
		Fetcher: &scanrun.Fetcher{CacheDir: t.TempDir(), Client: server.Client()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 2 || len(manifest.Missing) != 1 || manifest.Missing[0] != "tool darwin/arm64" {
		t.Fatalf("manifest = %+v", manifest)
	}
	paths := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		paths[artifact.Path] = true
	}
	if !paths["tool/1.0/tool_linux_x86"] || !paths["tool/1.0/org/example/plugin/1.0/plugin-1.0.jar"] {
		t.Fatalf("bundle layout must match offline Resolve: %v", paths)
	}

	store := t.TempDir()
	if _, err := Import(catalog, out, store); err != nil {
		t.Fatal(err)
	}
	// The imported store is what offline mode resolves to.
	location, _ := scancatalog.DistributionConfig{Mode: scancatalog.ModeOffline, BundleDir: store}.Resolve(&catalog.Scanners[0], &catalog.Scanners[0].Distributions[0])
	if _, err := (&scanrun.Fetcher{CacheDir: t.TempDir()}).Fetch(context.Background(), location, "tool", true); err != nil {
		t.Fatalf("offline fetch from the imported store: %v", err)
	}
}

func TestImportRejects(t *testing.T) {
	catalog := testCatalog("https://example.test")
	write := func(dir string, manifest Manifest, files map[string][]byte) {
		for path, data := range files {
			full := filepath.Join(dir, filepath.FromSlash(path))
			_ = os.MkdirAll(filepath.Dir(full), 0o750)
			_ = os.WriteFile(full, data, 0o640)
		}
		encoded, _ := json.Marshal(manifest)
		_ = os.WriteFile(filepath.Join(dir, ManifestName), encoded, 0o640)
	}
	good := Artifact{ScannerID: "tool", Path: "tool/1.0/tool_linux_x86", SHA256: digest([]byte("binary-linux-amd64"))}

	corrupt := t.TempDir()
	write(corrupt, Manifest{Artifacts: []Artifact{good}}, map[string][]byte{good.Path: []byte("tampered")})
	store := t.TempDir()
	if _, err := Import(catalog, corrupt, store); !errors.Is(err, scanrun.ErrDigestMismatch) {
		t.Fatalf("corrupt artifact = %v", err)
	}
	if entries, _ := os.ReadDir(store); len(entries) != 0 {
		t.Fatal("nothing may be imported when one artifact fails")
	}

	foreign := t.TempDir()
	write(foreign, Manifest{Artifacts: []Artifact{{ScannerID: "tool", Path: "tool/9.9/evil", SHA256: digest([]byte("x"))}}}, map[string][]byte{"tool/9.9/evil": []byte("x")})
	if _, err := Import(catalog, foreign, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not an artifact of catalog") {
		t.Fatalf("foreign artifact = %v", err)
	}

	escape := t.TempDir()
	write(escape, Manifest{Artifacts: []Artifact{{ScannerID: "tool", Path: "../outside", SHA256: good.SHA256}}}, nil)
	if _, err := Import(catalog, escape, t.TempDir()); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("path traversal = %v", err)
	}
}
