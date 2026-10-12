package server

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

func TestConfiguredRunScope(t *testing.T) {
	cfg, err := repoconfig.Parse([]byte(`version: 1
scanners:
  semgrep:
    scope: changed-files
  eslint:
    scope: partial
    paths: [web/]
  gosec:
    scope: full
`))
	if err != nil {
		t.Fatal(err)
	}
	pr := &configuredScopes{cfg: cfg, pullRequest: true, changed: []string{"a.go"}, changedKnown: true}
	cases := []struct {
		name     string
		scopes   *configuredScopes
		producer string
		scope    string
		paths    []string
		declared bool
	}{
		{"no config assumes full", nil, "semgrep", store.ProducerScopeFull, nil, false},
		{"unreadable config is never full", &configuredScopes{unknown: true}, "gosec", store.ProducerScopePartial, nil, false},
		{"unlisted tool assumes full", pr, "trivy", store.ProducerScopeFull, nil, false},
		{"full", pr, "gosec", store.ProducerScopeFull, nil, true},
		{"partial paths", pr, "eslint", store.ProducerScopePartial, []string{"web"}, true},
		{"changed-files on a PR", pr, "semgrep", store.ProducerScopePartial, []string{"a.go"}, true},
		{"changed-files on a branch", &configuredScopes{cfg: cfg}, "semgrep", store.ProducerScopeFull, nil, true},
		{"changed-files, PR files unknown", &configuredScopes{cfg: cfg, pullRequest: true}, "semgrep", store.ProducerScopePartial, nil, true},
	}
	for _, tc := range cases {
		scope, paths, declared := tc.scopes.runScope(tc.producer)
		if scope != tc.scope || !slices.Equal(paths, tc.paths) || declared != tc.declared {
			t.Errorf("%s: got (%s, %v, %v), want (%s, %v, %v)", tc.name, scope, paths, declared, tc.scope, tc.paths, tc.declared)
		}
	}
}

func TestSARIFProducerRunsUploadDeclarationWinsOverConfig(t *testing.T) {
	cfg, err := repoconfig.Parse([]byte("version: 1\nscanners:\n  gosec:\n    scope: partial\n    paths: [cmd]\n"))
	if err != nil {
		t.Fatal(err)
	}
	scopes := &configuredScopes{cfg: cfg}
	doc := mustParseSARIF(t, producerRunSARIF)

	runs := sarifProducerRuns(doc, store.SnapshotArtifact{}, scopes)
	if runs[0].Producer != "gosec" || runs[0].Scope != store.ProducerScopePartial || !slices.Equal(runs[0].ScopePaths, []string{"cmd"}) || !runs[0].ScopeDeclared {
		t.Fatalf("undeclared upload: got %+v, want partial [cmd] from .hibou.yaml", runs[0])
	}

	full := store.ProducerScopeFull
	runs = sarifProducerRuns(doc, store.SnapshotArtifact{Scope: &full}, scopes)
	if runs[0].Scope != store.ProducerScopeFull || len(runs[0].ScopePaths) != 0 {
		t.Fatalf("declared upload: got %+v, want the upload's full scope", runs[0])
	}
}

type scannerScopeForge struct {
	*compareCountingForge
	config string
	reads  atomic.Int32
}

func (f *scannerScopeForge) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	f.reads.Add(1)
	return []byte(f.config), nil
}

// changed-files on a PR resolves to the PR's files from one forge
// comparison; a snapshot whose uploads all declared a scope reads nothing.
func TestResolveConfiguredScopesChangedFilesOnPR(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	fake := &scannerScopeForge{
		compareCountingForge: &compareCountingForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}},
		config:               "version: 1\nscanners:\n  semgrep:\n    scope: changed-files\n",
	}
	srv.forges = map[string]forge.Provider{"github": fake}
	srv.repoConfigLoader = repoconfig.NewLoader(srv.forges, srv.log)
	repo := createUploadTestRepository(t, srv, org)
	// repoCoordinates needs owner/name; the test repository has none.
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	if _, err := srv.db.Exec(`UPDATE repositories SET provider_id = 'acme/app' WHERE id = $1`, repo.ID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "refs/pull/9", store.RefTypePullRequest, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &store.Snapshot{ID: uuid.New(), RefID: ref.ID, CommitSHA: "head", BaseCommitSHA: "base"}

	full := store.ProducerScopeFull
	if scopes := srv.resolveConfiguredScopes(ctx, snapshot, []store.SnapshotArtifact{{Kind: "sarif", Scope: &full}}); scopes != nil || fake.reads.Load() != 0 {
		t.Fatalf("declared uploads must not read .hibou.yaml: %+v reads=%d", scopes, fake.reads.Load())
	}
	scopes := srv.resolveConfiguredScopes(ctx, snapshot, []store.SnapshotArtifact{{Kind: "sarif"}})
	scope, paths, declared := scopes.runScope("semgrep")
	if scope != store.ProducerScopePartial || !slices.Equal(paths, []string{"a.go"}) || !declared {
		t.Fatalf("semgrep on PR = (%s, %v, %v), want partial [a.go]", scope, paths, declared)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("forge comparisons = %d, want 1", fake.calls.Load())
	}
}
