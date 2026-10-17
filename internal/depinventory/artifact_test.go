package depinventory

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanTargetsMixedArchive(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "stage", "lib")
	writeJar(t, filepath.Join(lib, "jackson-databind-2.15.2.jar"), map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Version: 2.15.2\n",
		"META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties": "groupId=com.fasterxml.jackson.core\nartifactId=jackson-databind\nversion=2.15.2\n",
	})
	writeJar(t, filepath.Join(lib, "mystery.jar"), map[string]string{"com/x/Y.class": "\xca\xfe\xba\xbe"})
	if err := os.WriteFile(filepath.Join(root, "stage", "libnative.so"), []byte("\x7fELFnative"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stage", "README.md"), []byte("docs"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The test binary itself is a Go binary with build info.
	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	if err := copyFile(self, filepath.Join(root, "stage", "app")); err != nil {
		t.Fatal(err)
	}

	// Wrap the staging tree in a zip: the mixed delivery of ADR-046 §4.2.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	_ = filepath.Walk(filepath.Join(root, "stage"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Join(root, "stage"), p)
		f, _ := w.Create(filepath.ToSlash(rel))
		data, _ := os.ReadFile(p)
		_, _ = f.Write(data)
		return nil
	})
	_ = w.Close()
	delivery := filepath.Join(root, "delivery.zip")
	if err := os.WriteFile(delivery, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	inv, err := ScanTargets(context.Background(), []string{delivery}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]Component{}
	for _, c := range inv.Components {
		names[c.Name] = c
	}
	jackson, ok := names["com.fasterxml.jackson.core:jackson-databind"]
	if !ok || jackson.Version != "2.15.2" || jackson.Resolution != ResolutionArtifact {
		t.Errorf("jackson from the nested jar: %+v (%d components)", jackson, len(inv.Components))
	}
	if !strings.Contains(jackson.Path, "delivery.zip!/lib/jackson-databind-2.15.2.jar") {
		t.Errorf("path inside the archive: %q", jackson.Path)
	}
	goModules := 0
	for _, c := range inv.Components {
		if c.Ecosystem == "go" {
			goModules++
		}
	}
	if goModules == 0 {
		t.Error("the Go binary's modules must be listed")
	}
	types := map[string]bool{}
	for _, u := range inv.Unidentified {
		types[u.Type] = true
	}
	if !types["native library"] || !types["java archive without Maven metadata"] {
		t.Errorf("unidentified files must be listed: %+v", inv.Unidentified)
	}
	for _, u := range inv.Unidentified {
		if filepath.Base(u.Path) == "README.md" {
			t.Error("documentation is not reported as unidentified")
		}
	}
	if len(inv.Targets) != 1 || inv.Targets[0].SHA256 == "" || inv.Targets[0].Kind != KindArchive {
		t.Errorf("target summary: %+v", inv.Targets)
	}
}
