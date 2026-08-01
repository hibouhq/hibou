package comparison

import "testing"

func newCodeTestDiff() *CoverageDiff {
	return &CoverageDiff{Files: []CoverageFileDelta{
		{FilePath: "src/app.ts", Change: "regressed"},
		{FilePath: "src/util.ts", Change: "improved"},
		{FilePath: "docs/readme.md", Change: "added"},
	}}
}

func TestApplyNewCodeLensCountsOnlyInstrumentedChangedLines(t *testing.T) {
	diff := newCodeTestDiff()
	changed := map[string][]int{
		// 10 and 11 are instrumented (one covered, one not); 99 is a changed
		// comment — not instrumented, so it must not dilute the ratio.
		"src/app.ts": {10, 11, 99},
	}
	headLines := map[string][]PatchLine{
		"src/app.ts": {{Number: 10, Hits: 3}, {Number: 11, Hits: 0}, {Number: 12, Hits: 1}},
	}

	ApplyNewCodeLens(diff, changed, headLines, nil, false)

	file := diff.Files[0]
	if file.NewLines != 2 || file.NewCovered != 1 {
		t.Fatalf("file new counts = %d/%d, want 1/2 measurable", file.NewCovered, file.NewLines)
	}
	if file.NewLineRate == nil || *file.NewLineRate != 0.5 {
		t.Fatalf("file new_line_rate = %v, want 0.5", file.NewLineRate)
	}
	// Line 12 is covered but unchanged: it belongs to old code, not this lens.
	if diff.NewLines != 2 || diff.NewCovered != 1 {
		t.Fatalf("aggregate = %d/%d, want 1/2", diff.NewCovered, diff.NewLines)
	}
	if diff.NewLineRate == nil || *diff.NewLineRate != 0.5 {
		t.Fatalf("aggregate new_line_rate = %v, want 0.5", diff.NewLineRate)
	}
}

// A docs-only change has nothing measurable: the rate must stay nil so the UI
// can say "not measurable" instead of showing 0% or 100%.
func TestApplyNewCodeLensLeavesRateNilWhenNothingMeasurable(t *testing.T) {
	diff := newCodeTestDiff()
	changed := map[string][]int{"docs/readme.md": {1, 2, 3}}
	headLines := map[string][]PatchLine{"src/app.ts": {{Number: 10, Hits: 1}}}

	ApplyNewCodeLens(diff, changed, headLines, nil, false)

	if diff.NewLineRate != nil || diff.NewLines != 0 {
		t.Fatalf("expected nothing measurable, got %d lines rate=%v", diff.NewLines, diff.NewLineRate)
	}
	for _, file := range diff.Files {
		if file.NewLineRate != nil {
			t.Fatalf("file %s got a new_line_rate with no instrumented changed lines", file.FilePath)
		}
	}
}

// Coverage tools emit prefixed paths (Go module, Java package roots) while the
// forge diff is repo-relative; the lens must reconcile them and attribute the
// counts to the right coverage-diff row.
func TestApplyNewCodeLensReconcilesPrefixedCoveragePaths(t *testing.T) {
	diff := &CoverageDiff{Files: []CoverageFileDelta{
		{FilePath: "github.com/acme/app/internal/svc/handler.go", Change: "improved"},
	}}
	changed := map[string][]int{"internal/svc/handler.go": {5, 6}}
	headLines := map[string][]PatchLine{
		"github.com/acme/app/internal/svc/handler.go": {{Number: 5, Hits: 2}, {Number: 6, Hits: 4}},
	}

	ApplyNewCodeLens(diff, changed, headLines, nil, false)

	if diff.Files[0].NewLines != 2 || diff.Files[0].NewCovered != 2 {
		t.Fatalf("prefixed path not reconciled: %+v", diff.Files[0])
	}
	if diff.NewLineRate == nil || *diff.NewLineRate != 1 {
		t.Fatalf("aggregate rate = %v, want 1", diff.NewLineRate)
	}
}

func TestApplyNewCodeLensHonorsExcludeGlobs(t *testing.T) {
	diff := newCodeTestDiff()
	changed := map[string][]int{"src/app.ts": {10}}
	headLines := map[string][]PatchLine{"src/app.ts": {{Number: 10, Hits: 0}}}

	ApplyNewCodeLens(diff, changed, headLines, []string{"src/**"}, false)

	if diff.NewLines != 0 {
		t.Fatalf("excluded file counted: %d new lines", diff.NewLines)
	}
}

// Truncation must survive even with no measurable lines, so the UI can say the
// number covers only the first N files.
func TestApplyNewCodeLensCarriesTruncation(t *testing.T) {
	diff := newCodeTestDiff()
	ApplyNewCodeLens(diff, nil, nil, nil, true)
	if !diff.NewCodeTruncated {
		t.Fatal("truncation flag lost")
	}
}

func TestApplyNewCodeLensNilDiffIsSafe(t *testing.T) {
	ApplyNewCodeLens(nil, map[string][]int{"a": {1}}, nil, nil, false)
}
