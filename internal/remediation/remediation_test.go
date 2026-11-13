package remediation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testBackend struct {
	generate func(string, Unit) error
	verify   func(string, Unit) (Verification, error)
}

func (b testBackend) Validate(Unit) error { return nil }
func (b testBackend) Generate(_ context.Context, root string, u Unit) (UnitResult, error) {
	if b.generate != nil {
		if err := b.generate(root, u); err != nil {
			return UnitResult{}, err
		}
	}
	return UnitResult{ID: u.ID}, nil
}
func (b testBackend) Verify(_ context.Context, root string, u Unit, _ UnitResult) (Verification, error) {
	if b.verify != nil {
		return b.verify(root, u)
	}
	return Verification{true, true, true}, nil
}

func repository(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	root := t.TempDir()
	for file, data := range files {
		p := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	home := t.TempDir()
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"add", "."},
		{"-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--quiet", "-m", "baseline"},
	} {
		if _, err := gitOutput(t.Context(), root, home, args...); err != nil {
			t.Fatal(err)
		}
	}
	out, err := gitOutput(t.Context(), root, home, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(out))
}

func testUnit() Unit {
	return Unit{
		ID: "web", Manager: "npm", Manifest: "package.json", Lockfile: "package-lock.json",
		RequiredFiles: []string{"package.json", "package-lock.json"},
		WritableFiles: []string{"package.json", "package-lock.json"},
		Vulns:         []string{"TEST-1"}, UpgradeLevel: "patch",
		InputSHA256: map[string]string{"package.json": digest([]byte("{}\n")), "package-lock.json": digest([]byte("{}\n"))},
	}
}

func TestGenerateIsolatedVerifiedBatch(t *testing.T) {
	files := map[string]string{"package.json": "{\"version\":\"1.0.0\"}\n", "package-lock.json": "{\"version\":\"1.0.0\"}\n"}
	root, sha := repository(t, files)
	// Dirty files are not input and must not be overwritten during generation.
	dirty := []byte("{\"unsaved-work\":true}\n")
	if err := os.WriteFile(filepath.Join(root, "package.json"), dirty, 0o644); err != nil {
		t.Fatal(err)
	}
	engine := Engine{TempDir: t.TempDir(), Backend: testBackend{generate: func(dir string, u Unit) error {
		for _, file := range u.WritableFiles {
			p := filepath.Join(dir, file)
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if string(data) != files[file] {
				t.Fatal("generation did not start at committed base")
			}
			if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(data), "1.0.0", "1.0.1")), 0o644); err != nil {
				return err
			}
		}
		return nil
	}}}
	unit := testUnit()
	for file, data := range files {
		unit.InputSHA256[file] = digest([]byte(data))
	}
	artifact, err := engine.Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Changes) != 2 || artifact.SHA256 != digest(artifact.Patch) || artifact.BaseSHA != sha {
		t.Fatalf("incorrect artifact: %+v", artifact)
	}
	for _, file := range testUnit().RequiredFiles {
		if !strings.Contains(string(artifact.Patch), "a/"+file) {
			t.Fatalf("patch omits %s", file)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil || string(data) != string(dirty) {
		t.Fatalf("generation modified working tree: %s, %v", data, err)
	}
	remaining, err := os.ReadDir(engine.TempDir)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("workspace leaked: %v, %v", remaining, err)
	}
}

func TestGenerateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		generate func(string, Unit) error
		verify   func(string, Unit) (Verification, error)
		want     string
	}{
		{"command failure", func(string, Unit) error { return errors.New("relock failed") }, nil, "relock failed"},
		{"missing lockfile", func(root string, _ Unit) error { return os.Remove(filepath.Join(root, "package-lock.json")) }, nil, "removed"},
		{"unverified consistency", nil, func(string, Unit) (Verification, error) { return Verification{false, true, true}, nil }, "verification failed"},
		{"remaining vulnerabilities", nil, func(string, Unit) (Verification, error) { return Verification{true, false, true}, nil }, "verification failed"},
		{"introduced vulnerabilities", nil, func(string, Unit) (Verification, error) { return Verification{true, true, false}, nil }, "verification failed"},
		{"verification error", nil, func(string, Unit) (Verification, error) { return Verification{}, errors.New("registry unavailable") }, "registry unavailable"},
		{"verification modifies lockfile", nil, func(root string, _ Unit) (Verification, error) {
			err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{\"silently-relocked\":true}\n"), 0o644)
			return Verification{true, true, true}, err
		}, "verification unexpectedly modified"},
		{"unexpected output", func(root string, _ Unit) error {
			return os.WriteFile(filepath.Join(root, "unexpected.txt"), []byte("bad"), 0o644)
		}, nil, "unexpected"},
		{"modified index", func(root string, _ Unit) error {
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{\"fixed\":true}\n"), 0o644); err != nil {
				return err
			}
			_, err := gitOutput(context.Background(), root, root, "add", "package.json")
			return err
		}, nil, "baseline index"},
		{"symlink output", func(root string, _ Unit) error {
			p := filepath.Join(root, "package-lock.json")
			if err := os.Remove(p); err != nil {
				return err
			}
			return os.Symlink("/etc/passwd", p)
		}, nil, "unsafe"},
		{"no changes", nil, nil, ErrNoChanges.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, sha := repository(t, map[string]string{"package.json": "{}\n", "package-lock.json": "{}\n"})
			e := Engine{Backend: testBackend{tc.generate, tc.verify}, TempDir: t.TempDir()}
			a, err := e.Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{testUnit()}})
			if err == nil || !strings.Contains(err.Error(), tc.want) || a != nil {
				t.Fatalf("artifact=%v error=%v, want %s", a, err, tc.want)
			}
		})
	}
}

func TestRejectInvalidAndCoupledRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Request)
	}{
		{"path traversal", func(r *Request) { r.Units[0].RequiredFiles = append(r.Units[0].RequiredFiles, "../outside") }},
		{"git metadata", func(r *Request) { r.Units[0].RequiredFiles = append(r.Units[0].RequiredFiles, ".git/config") }},
		{"absolute path", func(r *Request) { r.Units[0].RequiredFiles = append(r.Units[0].RequiredFiles, "/tmp/outside") }},
		{"ambiguous units", func(r *Request) { u := testUnit(); u.ID = "other"; r.Units = append(r.Units, u) }},
		{"duplicate ID", func(r *Request) { r.Units = append(r.Units, testUnit()) }},
		{"missing SHA", func(r *Request) { r.BaseSHA = "" }},
		{"ref instead of SHA", func(r *Request) { r.BaseSHA = "main" }},
		{"undeclared output", func(r *Request) { r.Units[0].WritableFiles = append(r.Units[0].WritableFiles, "other.lock") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Repository: "/unused", BaseSHA: strings.Repeat("a", 40), Units: []Unit{testUnit()}}
			tc.mutate(&req)
			if _, _, err := validateRequest(req, testBackend{}); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestBatchFailureReturnsNoArtifact(t *testing.T) {
	root, sha := repository(t, map[string]string{"a/package.json": "{}\n", "b/package.json": "{}\n"})
	units := []Unit{
		{ID: "a", Manifest: "a/package.json", RequiredFiles: []string{"a/package.json"}, WritableFiles: []string{"a/package.json"}, Vulns: []string{"A"}, InputSHA256: map[string]string{"a/package.json": digest([]byte("{}\n"))}},
		{ID: "b", Manifest: "b/package.json", RequiredFiles: []string{"b/package.json"}, WritableFiles: []string{"b/package.json"}, Vulns: []string{"B"}, InputSHA256: map[string]string{"b/package.json": digest([]byte("{}\n"))}},
	}
	e := Engine{TempDir: t.TempDir(), Backend: testBackend{generate: func(dir string, u Unit) error {
		if u.ID == "b" {
			return errors.New("second module failed")
		}
		return os.WriteFile(filepath.Join(dir, u.Manifest), []byte("{\"fixed\":true}\n"), 0o644)
	}}}
	a, err := e.Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: units})
	if err == nil || a != nil {
		t.Fatalf("partial artifact exposed: %v %v", a, err)
	}
}

func TestBranchNameSingleSlash(t *testing.T) {
	sha, artifact := strings.Repeat("a", 40), strings.Repeat("b", 64)
	var names []string
	for _, target := range []string{"main", "release/3.4", "release-3.4", "support/a/b", "🚀", "Feature/My_BRANCH"} {
		name, err := BranchName(target, sha, artifact)
		if err != nil || strings.Count(name, "/") != 1 || !strings.HasPrefix(name, "hibou/fix-") {
			t.Fatalf("%q: %s %v", target, name, err)
		}
		again, err := BranchName(target, sha, artifact)
		if err != nil || name != again {
			t.Fatal("branch naming is not deterministic")
		}
		for _, prior := range names {
			if prior == name {
				t.Fatal("branch collision")
			}
		}
		names = append(names, name)
	}
	if _, err := BranchName("main", sha, "invalid"); err == nil {
		t.Fatal("invalid artifact accepted")
	}
}

func TestCancelledGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	root, sha := repository(t, map[string]string{"package.json": "{}", "package-lock.json": "{}"})
	a, err := (Engine{Backend: testBackend{}}).Generate(ctx, Request{Repository: root, BaseSHA: sha, Units: []Unit{testUnit()}})
	if err == nil || a != nil {
		t.Fatalf("cancelled generation succeeded: %v %v", a, err)
	}
}
