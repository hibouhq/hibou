package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func generatedArtifact(t *testing.T) (string, *Artifact) {
	t.Helper()
	root, sha := repository(t, map[string]string{"package.json": "{}\n", "package-lock.json": "{}\n"})
	e := Engine{Backend: testBackend{generate: func(dir string, u Unit) error {
		for _, file := range u.WritableFiles {
			if err := os.WriteFile(filepath.Join(dir, file), []byte("{\"fixed\":true}\n"), 0o644); err != nil {
				return err
			}
		}
		return nil
	}}}
	a, err := e.Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{testUnit()}})
	if err != nil {
		t.Fatal(err)
	}
	return root, a
}

func TestApplyBatchAndRetry(t *testing.T) {
	root, a := generatedArtifact(t)
	unrelated := filepath.Join(root, "unrelated.txt")
	if err := os.WriteFile(unrelated, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Apply(t.Context(), root, *a)
	if err != nil || result.AlreadyApplied {
		t.Fatalf("%v %v", result, err)
	}
	for _, change := range a.Changes {
		data, err := os.ReadFile(filepath.Join(root, change.Path))
		if err != nil || digest(data) != change.After {
			t.Fatalf("incorrect applied output: %v", err)
		}
	}
	data, err := os.ReadFile(unrelated)
	if err != nil || string(data) != "keep me" {
		t.Fatal("unrelated change lost")
	}
	result, err = Apply(t.Context(), root, *a)
	if err != nil || !result.AlreadyApplied {
		t.Fatalf("retry was not reconciled: %v %v", result, err)
	}
	index, err := gitOutput(t.Context(), root, t.TempDir(), "diff", "--cached", "--name-only")
	if err != nil || len(index) != 0 {
		t.Fatal("apply staged changes")
	}
}

func TestApplyRejectsDirtyAndCorruptBatches(t *testing.T) {
	for _, name := range []string{"dirty", "staged", "corrupt", "extra-path", "wrong-head", "mixed"} {
		t.Run(name, func(t *testing.T) {
			root, a := generatedArtifact(t)
			switch name {
			case "dirty":
				if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("my work"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "staged":
				if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("staged work"), 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := gitOutput(t.Context(), root, t.TempDir(), "add", "package.json"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				a.Patch = append(a.Patch, 'x')
			case "extra-path":
				a.Patch = append(a.Patch, []byte("diff --git a/extra b/extra\nnew file mode 100644\n--- /dev/null\n+++ b/extra\n@@ -0,0 +1 @@\n+unexpected\n")...)
				a.SHA256 = digest(a.Patch)
			case "wrong-head":
				a.BaseSHA = strings.Repeat("a", 40)
			case "mixed":
				if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{\"fixed\":true}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if result, err := Apply(t.Context(), root, *a); err == nil || result != nil {
				t.Fatalf("invalid batch applied: %v %v", result, err)
			}
			data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
			if err != nil || string(data) != "{}\n" {
				t.Fatal("failure partially applied batch")
			}
		})
	}
}
