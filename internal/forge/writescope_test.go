package forge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckWriteBranch(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"hibou/configure", "hibou/fix/release-1.2/ab12cd", "hibou/notices"} {
		if err := CheckWriteBranch(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"main", "master", "release/1.2", "hibou/", "hibou", " hibou/x", "hibou/../main", "refs/heads/hibou/x", "hibou/x/", "hibou/a b", "feature/hibou/x", ""} {
		if err := CheckWriteBranch(bad); !errors.Is(err, ErrBranchOutsideNamespace) {
			t.Errorf("%q accepted (err %v)", bad, err)
		}
	}
}

// A write outside hibou/** never reaches the forge, on every provider.
func TestProvidersRefuseWritesOutsideTheNamespace(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	type writer interface {
		CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error
		CreateOrUpdateFile(ctx context.Context, owner, repo, filePath, branch, message string, content []byte) error
		CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error)
	}
	providers := map[string]writer{
		"github":  NewGitHub("id", "secret", "hook", WithAPIURL(server.URL)),
		"gitlab":  NewGitLab(server.URL, "id", "secret", "hook"),
		"forgejo": NewForgejo(server.URL, "id", "secret", "hook", "token"),
	}
	ctx := context.Background()
	for name, p := range providers {
		if err := p.CreateBranch(ctx, "acme", "app", "main", "abc"); !errors.Is(err, ErrBranchOutsideNamespace) {
			t.Errorf("%s CreateBranch(main) = %v", name, err)
		}
		if err := p.CreateOrUpdateFile(ctx, "acme", "app", ".hibou.yaml", "release/1.2", "m", []byte("x")); !errors.Is(err, ErrBranchOutsideNamespace) {
			t.Errorf("%s CreateOrUpdateFile(release/1.2) = %v", name, err)
		}
		if _, err := p.CreatePullRequest(ctx, "acme", "app", CreatePROptions{Head: "main", Base: "develop"}); !errors.Is(err, ErrBranchOutsideNamespace) {
			t.Errorf("%s CreatePullRequest(head main) = %v", name, err)
		}
	}
	if called {
		t.Fatal("a refused write reached the forge")
	}
}
