package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckoutManifestsDistinguishesTagFromSameNamedBranch(t *testing.T) {
	origin := t.TempDir()
	gitOrSkip(t, origin, "init", "-q", "-b", "main")
	gitOrSkip(t, origin, "config", "uploadpack.allowFilter", "true")
	file := filepath.Join(origin, "go.mod")
	if err := os.WriteFile(file, []byte("module example.com/old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOrSkip(t, origin, "add", "go.mod")
	gitOrSkip(t, origin, "commit", "-qm", "release")
	released := gitOrSkip(t, origin, "rev-parse", "HEAD")
	gitOrSkip(t, origin, "tag", "v1.0.0")
	if err := os.WriteFile(file, []byte("module example.com/new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitOrSkip(t, origin, "commit", "-qam", "new branch content")
	gitOrSkip(t, origin, "branch", "v1.0.0")
	checkout, err := CheckoutManifests(context.Background(), t.TempDir(), origin, "refs/tags/v1.0.0", "", "", func(p string) bool { return p == "go.mod" })
	if err != nil {
		t.Fatal(err)
	}
	defer checkout.Close()
	if checkout.Commit != released {
		t.Fatalf("checked out %s instead of tagged commit %s", checkout.Commit, released)
	}
}
