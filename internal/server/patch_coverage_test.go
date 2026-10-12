package server

import (
	"context"
	"math"
	"testing"

	"github.com/hibouhq/hibou/internal/comparison"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

func float64Ptr(v float64) *float64 { return &v }

func coverageDiffWithRates(base, head float64) *comparison.CoverageDiff {
	return &comparison.CoverageDiff{
		Base: &comparison.CoverageTotals{LineRate: float64Ptr(base)},
		Head: &comparison.CoverageTotals{LineRate: float64Ptr(head)},
	}
}

func coverageGateConfig(thresholds repoconfig.CoverageThresholds) *repoconfig.RepoConfig {
	return &repoconfig.RepoConfig{
		Version: repoconfig.CurrentVersion,
		QualityGates: []repoconfig.QualityGate{{
			Branches: []string{"main"},
			Coverage: &thresholds,
		}},
	}
}

func TestEvaluateCoverageGate(t *testing.T) {
	tests := []struct {
		name       string
		thresholds repoconfig.CoverageThresholds
		diff       *comparison.CoverageDiff
		patch      *comparison.PatchCoverage
		wantReason int
	}{
		{
			name:       "min_coverage pass",
			thresholds: repoconfig.CoverageThresholds{MinCoverage: float64Ptr(60)},
			diff:       coverageDiffWithRates(0.9, 0.85),
			wantReason: 0,
		},
		{
			name:       "min_coverage fail",
			thresholds: repoconfig.CoverageThresholds{MinCoverage: float64Ptr(90)},
			diff:       coverageDiffWithRates(0.9, 0.85),
			wantReason: 1,
		},
		{
			name:       "grace fail on regression beyond slack",
			thresholds: repoconfig.CoverageThresholds{Grace: float64Ptr(2)},
			diff:       coverageDiffWithRates(0.90, 0.85), // 5% drop > 2% grace
			wantReason: 1,
		},
		{
			name:       "grace pass within slack",
			thresholds: repoconfig.CoverageThresholds{Grace: float64Ptr(6)},
			diff:       coverageDiffWithRates(0.90, 0.85),
			wantReason: 0,
		},
		{
			name:       "diff_minimum fail on low patch coverage",
			thresholds: repoconfig.CoverageThresholds{DiffMinimum: float64Ptr(80)},
			diff:       coverageDiffWithRates(0.90, 0.90),
			patch:      &comparison.PatchCoverage{Rate: float64Ptr(0.5)},
			wantReason: 1,
		},
		{
			name:       "diff_minimum pass",
			thresholds: repoconfig.CoverageThresholds{DiffMinimum: float64Ptr(80)},
			diff:       coverageDiffWithRates(0.90, 0.90),
			patch:      &comparison.PatchCoverage{Rate: float64Ptr(0.95)},
			wantReason: 0,
		},
		{
			name:       "diff_minimum skipped when patch coverage absent",
			thresholds: repoconfig.CoverageThresholds{DiffMinimum: float64Ptr(80)},
			diff:       coverageDiffWithRates(0.90, 0.90),
			patch:      nil,
			wantReason: 0,
		},
		{
			name:       "all three fail",
			thresholds: repoconfig.CoverageThresholds{MinCoverage: float64Ptr(95), Grace: float64Ptr(1), DiffMinimum: float64Ptr(90)},
			diff:       coverageDiffWithRates(0.90, 0.80),
			patch:      &comparison.PatchCoverage{Rate: float64Ptr(0.5)},
			wantReason: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reasons := evaluateCoverageGate(coverageGateConfig(tc.thresholds), "main", tc.diff, tc.patch)
			if len(reasons) != tc.wantReason {
				t.Fatalf("reasons = %d (%v), want %d", len(reasons), reasons, tc.wantReason)
			}
		})
	}
}

func TestEvaluateCoverageGateNoConfig(t *testing.T) {
	if reasons := evaluateCoverageGate(nil, "main", coverageDiffWithRates(0.1, 0.1), nil); reasons != nil {
		t.Fatalf("expected nil reasons for nil config, got %v", reasons)
	}
	// No coverage block on the matched gate => no coverage reasons.
	cfg := &repoconfig.RepoConfig{Version: repoconfig.CurrentVersion, QualityGates: []repoconfig.QualityGate{{Branches: []string{"main"}}}}
	if reasons := evaluateCoverageGate(cfg, "main", coverageDiffWithRates(0.1, 0.1), nil); len(reasons) != 0 {
		t.Fatalf("expected no reasons without coverage thresholds, got %v", reasons)
	}
}

// TestBuildPatchCoverageIntegration exercises the full server glue: a forge
// patch (changed lines) intersected with the head snapshot's persisted per-line
// coverage.
func TestBuildPatchCoverageIntegration(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	srv.cfg.CoverageStoreLines = true

	provider, ok := srv.forges["github"].(*discoveryTestForgeProvider)
	if !ok {
		t.Fatal("expected discoveryTestForgeProvider")
	}
	provider.comparePatchDiff = &forge.PatchDiff{
		Files: []forge.PatchFile{{Path: "foo.go", Status: "modified", AddedLines: []int{1, 2, 3}}},
	}

	// Repo with an owner/name providerID so repoCoordinates resolves.
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo, err := srv.queries.CreateRepository(context.Background(), org.ID, nil, uniqueName(t, "patchcov"), uniqueName(t, "patchcov"), "github", "acme/widget", "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	baseRef, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest("basesha"))
	if err != nil {
		t.Fatalf("CreateRef base: %v", err)
	}
	baseSnapshot, err := srv.queries.CreateSnapshot(context.Background(), baseRef.ID, "basecommit", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot base: %v", err)
	}

	headRef, err := srv.queries.CreateRef(context.Background(), repo.ID, "refs/pull/5", store.RefTypePullRequest, nil, nil, stringPtrForTest("headsha"))
	if err != nil {
		t.Fatalf("CreateRef head: %v", err)
	}
	headSnapshot, err := srv.queries.CreateSnapshot(context.Background(), headRef.ID, "headcommit", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot head: %v", err)
	}

	// foo.go: line 1 covered, line 2 uncovered, line 3 covered.
	cobertura := []byte(`<?xml version="1.0"?>
<coverage>
  <packages><package name="p"><classes>
    <class name="Foo" filename="foo.go">
      <lines>
        <line number="1" hits="2"/>
        <line number="2" hits="0"/>
        <line number="3" hits="1"/>
      </lines>
    </class>
  </classes></package></packages>
</coverage>`)
	srv.processCoverageUpload(context.Background(), headSnapshot.ID, cobertura, "cobertura")

	pc := srv.buildPatchCoverage(context.Background(), repo, baseSnapshot, headSnapshot, nil)
	if pc == nil {
		t.Fatal("expected patch coverage")
	}
	if pc.CoveredLines != 2 || pc.UncoveredLines != 1 {
		t.Fatalf("covered/uncovered = %d/%d, want 2/1", pc.CoveredLines, pc.UncoveredLines)
	}
	if pc.Rate == nil || math.Abs(*pc.Rate-2.0/3.0) > 0.0001 {
		t.Fatalf("rate = %v, want 0.667", pc.Rate)
	}
	if len(pc.Files) != 1 || pc.Files[0].FilePath != "foo.go" {
		t.Fatalf("files = %+v, want foo.go", pc.Files)
	}
	if len(pc.Files[0].UncoveredLineNumbers) != 1 || pc.Files[0].UncoveredLineNumbers[0] != 2 {
		t.Fatalf("uncovered lines = %v, want [2]", pc.Files[0].UncoveredLineNumbers)
	}
}

func TestBuildPatchCoverageNilWhenForgeHasNoPatch(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	srv.cfg.CoverageStoreLines = true
	// provider.comparePatchDiff left nil → degrade to nil patch coverage.

	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo, err := srv.queries.CreateRepository(context.Background(), org.ID, nil, uniqueName(t, "nopatch"), uniqueName(t, "nopatch"), "github", "acme/widget2", "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	baseRef, _ := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest("b"))
	baseSnapshot, _ := srv.queries.CreateSnapshot(context.Background(), baseRef.ID, "bc", store.SnapshotStatusComplete)
	headRef, _ := srv.queries.CreateRef(context.Background(), repo.ID, "refs/pull/6", store.RefTypePullRequest, nil, nil, stringPtrForTest("h"))
	headSnapshot, _ := srv.queries.CreateSnapshot(context.Background(), headRef.ID, "hc", store.SnapshotStatusComplete)

	if pc := srv.buildPatchCoverage(context.Background(), repo, baseSnapshot, headSnapshot, nil); pc != nil {
		t.Fatalf("expected nil patch coverage when forge returns no patch, got %+v", pc)
	}
}
