package remediation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testTool(t *testing.T, body string) Tool {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture executable")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "manager")
	script := "#!/bin/sh\nif [ \"$1\" = '--version' ]; then echo fixture-1; exit 0; fi\n" + body + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return Tool{Path: binary, VersionOutput: "fixture-1", PATH: os.Getenv("PATH")}
}

func TestToolDoesNotInheritServerSecrets(t *testing.T) {
	t.Setenv("HIBOU_DATABASE_URL", "must-not-reach-child")
	tool := testTool(t, `test -z "$HIBOU_DATABASE_URL" || exit 7
test "$NPM_CONFIG_IGNORE_SCRIPTS" = true || exit 8
test "$HOME" != "$PWD" || exit 9
test "$*" = "install --package-lock-only --ignore-scripts --no-audit --no-fund" || exit 10`)
	root := t.TempDir()
	relocker := NativeRelocker{Manager: "npm", Tool: tool}
	if err := relocker.Relock(t.Context(), root, testUnit()); err != nil {
		t.Fatal(err)
	}
}

func TestToolFailsOnExitVersionAndCancellation(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	tool := testTool(t, "exit 17")
	if err := tool.Run(t.Context(), root, home, "lock"); err == nil {
		t.Fatal("nonzero command exit ignored")
	}

	tool.VersionOutput = "different-version"
	if err := tool.Run(t.Context(), root, home, "lock"); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("version mismatch not rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := tool.Run(ctx, root, home, "lock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestToolCancellationTerminatesProcessGroup(t *testing.T) {
	tool := testTool(t, "sleep 30")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := tool.Run(ctx, t.TempDir(), t.TempDir(), "lock")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("process group did not terminate promptly: %v (%s)", err, time.Since(start))
	}
}

func TestRelockerRejectsOtherManagers(t *testing.T) {
	r := NativeRelocker{Manager: "npm", Tool: testTool(t, "exit 0")}
	u := testUnit()
	u.Manager, u.Lockfile = "pnpm", "pnpm-lock.yaml"
	if err := r.Validate(u); err == nil {
		t.Fatal("pnpm silently converted to npm")
	}
	u = testUnit()
	u.Lockfile = "npm-shrinkwrap.json"
	if err := r.Validate(u); err == nil {
		t.Fatal("untested lockfile accepted")
	}
}

type testRelocker struct{ err error }

func (testRelocker) Validate(Unit) error                          { return nil }
func (r testRelocker) Relock(context.Context, string, Unit) error { return r.err }

func TestSCALIBRRelockErrorCannotReturnArtifact(t *testing.T) {
	original := `{"name":"app","version":"1.0.0","dependencies":{"fixture-dependency":"1.0.0"}}`
	lock := "{}\n"
	root, sha := repository(t, map[string]string{"package.json": original, "package-lock.json": lock})
	u := testUnit()
	u.InputSHA256["package.json"] = digest([]byte(original))
	s := fixtureSCALIBR(t)
	s.Relocker = testRelocker{errors.New("native manager exited 1")}
	a, err := (Engine{Backend: s}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{u}})
	if err == nil || a != nil || !strings.Contains(err.Error(), "relock failed") {
		t.Fatalf("relock failure swallowed: %v, %v", a, err)
	}
}

func TestOmittedLockfileCannotBeHidden(t *testing.T) {
	original := `{"name":"app","version":"1.0.0","dependencies":{"fixture-dependency":"1.0.0"}}`
	root, sha := repository(t, map[string]string{"package.json": original, "poetry.lock": "{}"})
	u := Unit{ID: "root", Manager: "npm", Manifest: "package.json", RequiredFiles: []string{"package.json"}, WritableFiles: []string{"package.json"}, Vulns: []string{"TEST-1"}, InputSHA256: map[string]string{"package.json": digest([]byte(original))}}
	a, err := (Engine{Backend: fixtureSCALIBR(t)}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{u}})
	if err == nil || a != nil || !strings.Contains(err.Error(), "omitted") {
		t.Fatalf("omitted lockfile not rejected: %v, %v", a, err)
	}
}
