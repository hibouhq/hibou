package secretscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitOrSkip runs git in dir with a scratch identity; tests skip when git
// is not installed.
func gitOrSkip(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestCheckoutManifestsSelectsOnlyManifests(t *testing.T) {
	origin := t.TempDir()
	gitOrSkip(t, origin, "init", "-q", "-b", "main")
	// A partial clone from a local path needs the server side to allow
	// filtering, and fetching a commit by id needs it reachable in want.
	gitOrSkip(t, origin, "config", "uploadpack.allowFilter", "true")
	gitOrSkip(t, origin, "config", "uploadpack.allowReachableSHA1InWant", "true")
	write := func(rel, content string) {
		full := filepath.Join(origin, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/text v0.14.0\n")
	write("web/package.json", `{"name":"web","dependencies":{"left-pad":"1.3.0"}}`)
	write("web/package-lock.json", `{"name":"web","lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}`)
	write("main.go", "package main\n")
	write("docs/big.bin", strings.Repeat("x", 4096))
	gitOrSkip(t, origin, "add", ".")
	gitOrSkip(t, origin, "commit", "-q", "-m", "first")
	first := gitOrSkip(t, origin, "rev-parse", "HEAD")
	write("main.go", "package main\n\nfunc main() {}\n")
	gitOrSkip(t, origin, "commit", "-q", "-am", "second")
	second := gitOrSkip(t, origin, "rev-parse", "HEAD")

	selector := func(p string) bool {
		base := filepath.Base(p)
		return base == "go.mod" || base == "package.json" || base == "package-lock.json"
	}
	checkout, err := CheckoutManifests(context.Background(), t.TempDir(), origin, "main", "", "", selector)
	if err != nil {
		t.Fatalf("CheckoutManifests: %v", err)
	}
	defer checkout.Close()
	if checkout.Commit != second {
		t.Errorf("commit %s, want ref head %s", checkout.Commit, second)
	}
	want := []string{"go.mod", "web/package-lock.json", "web/package.json"}
	if strings.Join(checkout.Paths, ",") != strings.Join(want, ",") {
		t.Errorf("paths %v, want %v", checkout.Paths, want)
	}
	for _, p := range want {
		if _, err := os.Stat(filepath.Join(checkout.Dir, p)); err != nil {
			t.Errorf("%s not checked out: %v", p, err)
		}
	}
	for _, absent := range []string{"main.go", "docs/big.bin"} {
		if _, err := os.Stat(filepath.Join(checkout.Dir, absent)); err == nil {
			t.Errorf("%s was checked out although not selected", absent)
		}
	}
	if len(checkout.Digest) != 64 || checkout.TreeTruncated {
		t.Errorf("digest %q truncated=%v", checkout.Digest, checkout.TreeTruncated)
	}

	// The manifests did not change between the two commits: same digest.
	// Asking for the first commit explicitly must land on it.
	earlier, err := CheckoutManifests(context.Background(), t.TempDir(), origin, "main", first, "", selector)
	if err != nil {
		t.Fatalf("CheckoutManifests(first): %v", err)
	}
	defer earlier.Close()
	if earlier.Commit != first {
		t.Errorf("commit %s, want %s", earlier.Commit, first)
	}
	if earlier.Digest != checkout.Digest {
		t.Errorf("digest changed although manifests did not: %s vs %s", earlier.Digest, checkout.Digest)
	}
}

func TestSelectTreeEntriesDigestIsOrderIndependent(t *testing.T) {
	a := "100644 blob aaaa\tgo.mod\x00100644 blob bbbb\tweb/package.json\x00100644 blob cccc\tmain.go\x00"
	b := "100644 blob bbbb\tweb/package.json\x00100644 blob cccc\tmain.go\x00100644 blob aaaa\tgo.mod\x00"
	keep := func(p string) bool { return p != "main.go" }
	pathsA, digestA, _ := selectTreeEntries(a, keep)
	pathsB, digestB, _ := selectTreeEntries(b, keep)
	if digestA != digestB || len(pathsA) != 2 || strings.Join(pathsA, ",") != strings.Join(pathsB, ",") {
		t.Errorf("listing order must not change the digest: %v %s vs %v %s", pathsA, digestA, pathsB, digestB)
	}
	_, digestC, _ := selectTreeEntries("100644 blob aaab\tgo.mod\x00100644 blob bbbb\tweb/package.json\x00", keep)
	if digestC == digestA {
		t.Error("a changed blob must change the digest")
	}
}
