package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/store"
)

type treeTestForge struct {
	*discoveryTestForgeProvider
	listing *forge.TreeListing
	listRef string
}

func (f *treeTestForge) GetBranch(context.Context, string, string, string) (*forge.Branch, error) {
	return &forge.Branch{Name: "main", SHA: "head-sha"}, nil
}

func (f *treeTestForge) ListTree(_ context.Context, _, _, ref string) (*forge.TreeListing, error) {
	f.listRef = ref
	return f.listing, nil
}

func TestDetectRepoApplicabilityStoresResult(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	catalog, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	srv.scanCatalog = catalog
	fake := &treeTestForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}, listing: &forge.TreeListing{
		Paths: []string{"pom.xml", "src/main/java/App.java", "README.md"},
	}}
	srv.forges = map[string]forge.Provider{"github": fake}
	repo := createUploadTestRepository(t, srv, org)
	repo.ProviderID = "acme/app"

	stored, err := srv.detectRepoApplicability(context.Background(), repo, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if fake.listRef != "head-sha" || stored.CommitSHA != "head-sha" || stored.RefName != "main" {
		t.Fatalf("detection must list the head commit, not the moving branch: ref=%s stored=%+v", fake.listRef, stored)
	}
	var result applicability.Result
	if err := json.Unmarshal(stored.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != applicability.StatusComplete || len(result.Applicable) < 2 {
		t.Fatalf("result = %+v", result)
	}
	latest, err := srv.queries.GetLatestRepoApplicability(context.Background(), repo.ID)
	if err != nil || latest == nil || latest.ID != stored.ID {
		t.Fatalf("latest = %+v, %v", latest, err)
	}

	// A forge without tree support stores "unknown", not "nothing applies".
	srv.forges = map[string]forge.Provider{"github": fake.discoveryTestForgeProvider}
	unknown, err := srv.detectRepoApplicability(context.Background(), repo, "main", "")
	if err != nil || unknown.Status != applicability.StatusUnknown {
		t.Fatalf("unknown = %+v, %v", unknown, err)
	}
}

// An owner exclusion hiding code the org requires scanned waits for an
// approved exception for that path; one hiding nothing required applies.
func TestScopeOverridesRespectRequirements(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	catalog, _ := scancatalog.Load()
	srv.scanCatalog = catalog
	srv.forges = map[string]forge.Provider{"github": &treeTestForge{discoveryTestForgeProvider: &discoveryTestForgeProvider{id: "github"}, listing: &forge.TreeListing{
		Paths: []string{"pom.xml", "src/main/java/App.java", "generated/Gen.java", "samples/bad.py"},
	}}}
	repo := createUploadTestRepository(t, srv, org)
	repo.ProviderID = "acme/app"
	ctx := context.Background()
	requirement, err := srv.queries.UpsertScannerRequirement(ctx, org.ID, store.ScannerRequirement{Language: "java", Capability: "bytecode-security", Enforcement: "blocking"}, &admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"generated", "samples"} {
		if _, err := srv.queries.CreateRepoScopeOverride(ctx, repo.ID, store.RepoScopeOverride{Kind: "exclude", Path: path, Reason: "not product code"}); err != nil {
			t.Fatal(err)
		}
	}
	exclusions := func() map[string]applicability.OwnerExclusion {
		stored, err := srv.detectRepoApplicability(ctx, repo, "main", "sha")
		if err != nil {
			t.Fatal(err)
		}
		var result applicability.Result
		_ = json.Unmarshal(stored.Result, &result)
		out := map[string]applicability.OwnerExclusion{}
		for _, exclusion := range result.OwnerExclusions {
			out[exclusion.Path] = exclusion
		}
		return out
	}
	got := exclusions()
	if !got["samples"].Applied || got["generated"].Applied || got["generated"].Blocked == "" {
		t.Fatalf("before exception: %+v", got)
	}
	exception, err := srv.queries.CreateCoverageException(ctx, store.CoverageException{RepoID: repo.ID, RequirementID: requirement.ID, Scope: "generated", Reason: "protobuf output", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.queries.DecideCoverageException(ctx, org.ID, exception.ID, "approved", &admin.ID); err != nil {
		t.Fatal(err)
	}
	if got := exclusions(); !got["generated"].Applied {
		t.Fatalf("approved exception must let the exclusion apply: %+v", got)
	}
}
