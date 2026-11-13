package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedPublicationFilesMaterializeFromPinnedCommit(t *testing.T) {
	root, sha := repository(t, map[string]string{"package.json": "{}\n", "package-lock.json": "{}\n"})
	unit := testUnit()
	artifact, err := (Engine{TempDir: t.TempDir(), Backend: testBackend{generate: func(dir string, _ Unit) error {
		return os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{\"updated\":true}\n"), 0o600)
	}}}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		t.Fatal(err)
	}
	files, err := managedArtifactFiles(t.Context(), root, t.TempDir(), *artifact)
	if err != nil {
		t.Fatal(err)
	}
	if string(files["package-lock.json"]) != "{\"updated\":true}\n" {
		t.Fatalf("incorrect full generated file: %q", files)
	}
	data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil || string(data) != "{}\n" {
		t.Fatal("publication materialization modified original source")
	}
	artifact.Changes[0].After = strings.Repeat("0", 64)
	if _, err := managedArtifactFiles(t.Context(), root, t.TempDir(), *artifact); err == nil {
		t.Fatal("unverified generated content accepted")
	}
}
