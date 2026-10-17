package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
)

type compareCountingForge struct {
	*discoveryTestForgeProvider
	calls atomic.Int32
	fail  bool
}

func (f *compareCountingForge) ComparePatch(context.Context, string, string, string, string) (*forge.PatchDiff, error) {
	f.calls.Add(1)
	if f.fail {
		return nil, errors.New("403 rate limited")
	}
	return &forge.PatchDiff{Files: []forge.PatchFile{{Path: "a.go", Status: "modified", AddedLines: []int{3}, Hunks: "@@ -1 +1,3 @@\n+x\n"}}}, nil
}

// Each pair is asked of the forge once; presence stores it without hunks;
// the PR diff view upgrades such a row instead of serving it empty.
func TestPresenceComparisonCachesPathsOnly(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	fake := &compareCountingForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}}
	srv.forges = map[string]forge.Provider{"github": fake}
	repo := createUploadTestRepository(t, srv, org)
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo.ProviderID = "acme/app"
	ctx := context.Background()

	index, err := srv.presenceComparison(ctx, repo, "base", "head", true)
	if err != nil || !index.change("a.go").Changed || !index.change("b.go").Known {
		t.Fatalf("index = %+v, %v", index, err)
	}
	if _, err := srv.presenceComparison(ctx, repo, "base", "head", true); err != nil || fake.calls.Load() != 1 {
		t.Fatalf("second ask must hit the cache: calls=%d err=%v", fake.calls.Load(), err)
	}
	cached, _ := srv.queries.GetComparePatchCache(ctx, repo.ID, "base", "head")
	if cached == nil || !cached.PathsOnly || cached.Files[0].Hunks != "" || cached.Files[0].AddedLines != nil {
		t.Fatalf("presence must cache paths only: %+v", cached)
	}
	diff := srv.changedLinesForComparison(ctx, repo, fake, "base", "head")
	if diff == nil || diff.Files[0].Hunks == "" || fake.calls.Load() != 2 {
		t.Fatalf("the diff view must upgrade a paths-only row: %+v calls=%d", diff, fake.calls.Load())
	}
	// A later paths-only write never downgrades the full row.
	_ = srv.queries.UpsertComparePatchCache(ctx, repo.ID, "base", "head", store.ComparePatchCacheEntry{PathsOnly: true, Files: []store.ComparePatchCachedFile{{Path: "a.go"}}})
	if cached, _ := srv.queries.GetComparePatchCache(ctx, repo.ID, "base", "head"); cached.PathsOnly || cached.Files[0].Hunks == "" {
		t.Fatalf("full row downgraded: %+v", cached)
	}
}

// A failing forge is not asked again within the backoff window.
func TestPresenceComparisonBacksOffOnFailure(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	fake := &compareCountingForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}, fail: true}
	srv.forges = map[string]forge.Provider{"github": fake}
	repo := createUploadTestRepository(t, srv, org)
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo.ProviderID = "acme/app"
	for i := 0; i < 5; i++ {
		if _, err := srv.presenceComparison(context.Background(), repo, "b1", "h1", true); err == nil {
			t.Fatal("a failed comparison must report an error")
		}
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("forge asked %d times in the backoff window", fake.calls.Load())
	}
	// A failed or unasked comparison defers: unconfirmed, never fixed.
	checker := prefetchedChangeChecker("h1", map[string]comparisonIndex{})
	if change := checker("b1", "a.go"); !change.Deferred {
		t.Fatalf("missing comparison = %+v", change)
	}
}

// Reconcile asks the forge nothing when nothing disappeared under coverage,
// and at most the budget otherwise; beyond it findings stay unconfirmed.
func TestReconcileForgeBudget(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	fake := &compareCountingForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}}
	srv.forges = map[string]forge.Provider{"github": fake}
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	if _, err := srv.db.ExecContext(ctx, `UPDATE repositories SET provider_id = 'acme/app' WHERE id = $1`, repo.ID); err != nil {
		t.Fatal(err)
	}
	ref, _ := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	gosec := store.ProducerRunInput{Producer: "gosec", Scope: "full", Outcome: "completed"}

	first, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "c1", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, first.ID, "sast", "gosec", "kept", "a.go")
	recordRun(t, srv, first.ID, gosec)
	second, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "c2", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, second.ID, "sast", "gosec", "kept", "a.go")
	recordRun(t, srv, second.ID, gosec)
	srv.reconcileFindingPresence(ctx, second.ID)
	if fake.calls.Load() != 0 {
		t.Fatalf("nothing disappeared: forge asked %d times", fake.calls.Load())
	}

	// Five carried findings last seen at five different commits, all gone now.
	// A carried finding's last-seen commit is a snapshot's (ADR-049), so the
	// five commits get snapshots on a scratch ref.
	third, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "c3", store.SnapshotStatusComplete)
	recordRun(t, srv, third.ID, gosec)
	scratch, _ := srv.queries.CreateRef(ctx, repo.ID, "scratch", store.RefTypeBranch, nil, nil, nil)
	for i, base := range []string{"x1", "x2", "x3", "x4", "x5"} {
		fp := "gone-" + base
		if _, err := srv.queries.CreateSnapshot(ctx, scratch.ID, base, store.SnapshotStatusComplete); err != nil {
			t.Fatal(err)
		}
		seedPresenceFinding(t, srv, second.ID, "sast", "gosec", fp, "f"+string(rune('a'+i))+".go")
		if _, err := srv.db.ExecContext(ctx, `UPDATE snapshot_findings sf SET presence = 'unconfirmed', last_seen_snapshot_id = (SELECT s.id FROM snapshots s WHERE s.commit_sha = $1 ORDER BY s.created_at DESC LIMIT 1) FROM findings f WHERE f.id = sf.finding_id AND sf.snapshot_id = $2 AND f.fingerprint = $3`, base, second.ID, fp); err != nil {
			t.Fatal(err)
		}
	}
	srv.reconcileFindingPresence(ctx, third.ID)
	if got := fake.calls.Load(); got > presenceCompareBudget {
		t.Fatalf("forge asked %d times, budget %d", got, presenceCompareBudget)
	}
	unchecked := 0
	for _, row := range presenceByFingerprint(t, srv, third.ID) {
		if derefString(row.PresenceReason) == presence.ReasonChangeUnchecked {
			unchecked++
		}
	}
	if unchecked < 2 {
		t.Fatalf("findings beyond the budget must stay unconfirmed, got %d", unchecked)
	}
}

type pathsOnlyForge struct{ compareCountingForge }

func (f *pathsOnlyForge) ComparesPathsOnly() bool { return true }

func (f *pathsOnlyForge) ComparePatch(context.Context, string, string, string, string) (*forge.PatchDiff, error) {
	f.calls.Add(1)
	return &forge.PatchDiff{PathsOnly: true, Files: []forge.PatchFile{{Path: "a.go", Status: "modified"}}}, nil
}

// A forge with no line data (Forgejo): presence uses its paths; the PR
// diff view degrades without re-asking the forge on every page view.
func TestPathsOnlyForgeIsAskedOnce(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	fake := &pathsOnlyForge{compareCountingForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}}}
	srv.forges = map[string]forge.Provider{"github": fake}
	repo := createUploadTestRepository(t, srv, org)
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo.ProviderID = "acme/app"
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if diff := srv.changedLinesForComparison(ctx, repo, fake, "b", "h"); diff != nil {
			t.Fatal("patch coverage must degrade on a paths-only forge")
		}
	}
	index, err := srv.presenceComparison(ctx, repo, "b", "h", true)
	if err != nil || !index.change("a.go").Changed {
		t.Fatalf("presence must use the cached paths: %+v %v", index, err)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("forge asked %d times", fake.calls.Load())
	}
}
