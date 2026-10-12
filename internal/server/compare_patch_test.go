package server

import (
	"context"
	"testing"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func newComparePatchTestRepo(t *testing.T, srv *Server, org *store.Organization) *store.Repository {
	t.Helper()
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	return createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "cmp"),
		slug:          uniqueName(t, "cmp"),
		provider:      "github",
		providerID:    "acme/" + uniqueName(t, "cmp"),
		defaultBranch: "main",
	})
}

// The cache exists so a comparison page costs at most one forge round-trip:
// both SHAs are immutable, so a second look-up must never hit the provider.
func TestChangedLinesForComparisonCachesAcrossCalls(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := newComparePatchTestRepo(t, srv, org)
	provider := &discoveryTestForgeProvider{
		id: "github",
		comparePatchDiff: &forge.PatchDiff{
			Truncated: true,
			Files: []forge.PatchFile{{
				Path:       "src/app.ts",
				Status:     "modified",
				AddedLines: []int{10, 11},
				Hunks:      "@@ -1 +1 @@\n+changed\n",
			}},
		},
	}
	ctx := context.Background()

	first := srv.changedLinesForComparison(ctx, repo, provider, "base-sha", "head-sha")
	if first == nil || len(first.Files) != 1 {
		t.Fatalf("first call = %#v, want one changed file", first)
	}
	if provider.comparePatchCalls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.comparePatchCalls)
	}

	second := srv.changedLinesForComparison(ctx, repo, provider, "base-sha", "head-sha")
	if provider.comparePatchCalls != 1 {
		t.Fatalf("provider calls after cache hit = %d, want still 1", provider.comparePatchCalls)
	}
	if second == nil || len(second.Files) != 1 {
		t.Fatalf("cached call = %#v, want one changed file", second)
	}
	// Hunks must survive the round-trip: the annotated PR diff renders from
	// them, so a cache hit without them would blank every diff view.
	if second.Files[0].Hunks != first.Files[0].Hunks {
		t.Fatalf("cached hunks = %q, want %q", second.Files[0].Hunks, first.Files[0].Hunks)
	}
	if second.Files[0].Path != "src/app.ts" || len(second.Files[0].AddedLines) != 2 {
		t.Fatalf("cached file lost data: %#v", second.Files[0])
	}
	if !second.Truncated {
		t.Fatal("truncation flag lost through the cache")
	}
}

// A different SHA pair is a different comparison and must not be served the
// cached answer.
func TestChangedLinesForComparisonKeyedByBothSHAs(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := newComparePatchTestRepo(t, srv, org)
	provider := &discoveryTestForgeProvider{
		id:               "github",
		comparePatchDiff: &forge.PatchDiff{Files: []forge.PatchFile{{Path: "a.go", AddedLines: []int{1}}}},
	}
	ctx := context.Background()

	srv.changedLinesForComparison(ctx, repo, provider, "base-1", "head-1")
	srv.changedLinesForComparison(ctx, repo, provider, "base-1", "head-2")
	if provider.comparePatchCalls != 2 {
		t.Fatalf("provider calls = %d, want 2 for two distinct comparisons", provider.comparePatchCalls)
	}
}

// A provider that cannot compare (GitLab/Forgejo stubs return nil) must degrade
// to "no classification" so the classic view still renders.
func TestChangedLinesForComparisonDegradesWithoutProviderSupport(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := newComparePatchTestRepo(t, srv, org)
	ctx := context.Background()

	stub := &discoveryTestForgeProvider{id: "github"} // nil diff, nil error
	if got := srv.changedLinesForComparison(ctx, repo, stub, "base", "head"); got != nil {
		t.Fatalf("stub provider = %#v, want nil classification", got)
	}

	if got := srv.changedLinesForComparison(ctx, repo, nil, "base", "head"); got != nil {
		t.Fatalf("nil provider = %#v, want nil", got)
	}
}

func TestChangedLinesForComparisonSkipsDegenerateInputs(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := newComparePatchTestRepo(t, srv, org)
	provider := &discoveryTestForgeProvider{
		id:               "github",
		comparePatchDiff: &forge.PatchDiff{Files: []forge.PatchFile{{Path: "a.go", AddedLines: []int{1}}}},
	}
	ctx := context.Background()

	// Identical SHAs are not a comparison; missing SHAs cannot be one either.
	for _, pair := range [][2]string{{"same", "same"}, {"", "head"}, {"base", ""}} {
		if got := srv.changedLinesForComparison(ctx, repo, provider, pair[0], pair[1]); got != nil {
			t.Fatalf("pair %v = %#v, want nil", pair, got)
		}
	}
	if provider.comparePatchCalls != 0 {
		t.Fatalf("provider called %d times for degenerate inputs, want 0", provider.comparePatchCalls)
	}
}
