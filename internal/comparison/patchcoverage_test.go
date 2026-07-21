package comparison

import (
	"math"
	"testing"
)

func floatValue(t *testing.T, p *float64) float64 {
	t.Helper()
	if p == nil {
		t.Fatal("expected non-nil rate")
	}
	return *p
}

func TestBuildPatchCoverageBasic(t *testing.T) {
	changes := []PatchChange{
		{FilePath: "foo.go", AddedLines: []int{10, 11, 12, 13}},
	}
	// Lines 10,12 covered; 11 uncovered; 13 not instrumented (blank/comment).
	head := map[string][]PatchLine{
		"foo.go": {{Number: 10, Hits: 3}, {Number: 11, Hits: 0}, {Number: 12, Hits: 1}},
	}

	pc := BuildPatchCoverage(changes, head, nil, false)
	if pc == nil {
		t.Fatal("expected patch coverage")
	}
	if pc.CoveredLines != 2 || pc.UncoveredLines != 1 {
		t.Fatalf("covered/uncovered = %d/%d, want 2/1", pc.CoveredLines, pc.UncoveredLines)
	}
	if math.Abs(floatValue(t, pc.Rate)-2.0/3.0) > 0.0001 {
		t.Fatalf("rate = %f, want 0.6667", *pc.Rate)
	}
	if len(pc.Files) != 1 {
		t.Fatalf("file count = %d, want 1", len(pc.Files))
	}
	f := pc.Files[0]
	if len(f.UncoveredLineNumbers) != 1 || f.UncoveredLineNumbers[0] != 11 {
		t.Fatalf("uncovered line numbers = %v, want [11]", f.UncoveredLineNumbers)
	}
	if len(f.CoveredLineNumbers) != 2 {
		t.Fatalf("covered line numbers = %v, want 2 entries", f.CoveredLineNumbers)
	}
}

func TestBuildPatchCoverageNoInstrumentedChangedLines(t *testing.T) {
	// A docs-only PR: changed lines exist but none are instrumented.
	changes := []PatchChange{{FilePath: "README.md", AddedLines: []int{1, 2}}}
	head := map[string][]PatchLine{"foo.go": {{Number: 1, Hits: 1}}}
	if pc := BuildPatchCoverage(changes, head, nil, false); pc != nil {
		t.Fatalf("expected nil patch coverage, got %+v", pc)
	}
}

func TestBuildPatchCoverageExcludeGlobs(t *testing.T) {
	changes := []PatchChange{
		{FilePath: "foo.go", AddedLines: []int{1}},
		{FilePath: "foo_test.go", AddedLines: []int{1}},
		{FilePath: "testutil/helper.go", AddedLines: []int{1}},
	}
	head := map[string][]PatchLine{
		"foo.go":             {{Number: 1, Hits: 0}},
		"foo_test.go":        {{Number: 1, Hits: 1}},
		"testutil/helper.go": {{Number: 1, Hits: 1}},
	}
	pc := BuildPatchCoverage(changes, head, []string{"*_test.go", "testutil/**"}, false)
	if pc == nil {
		t.Fatal("expected patch coverage")
	}
	// Only foo.go survives the excludes; it is uncovered.
	if len(pc.Files) != 1 || pc.Files[0].FilePath != "foo.go" {
		t.Fatalf("files = %+v, want only foo.go", pc.Files)
	}
	if pc.CoveredLines != 0 || pc.UncoveredLines != 1 {
		t.Fatalf("covered/uncovered = %d/%d, want 0/1", pc.CoveredLines, pc.UncoveredLines)
	}
	if math.Abs(floatValue(t, pc.Rate)-0.0) > 0.0001 {
		t.Fatalf("rate = %f, want 0", *pc.Rate)
	}
}

func TestBuildPatchCoveragePathNormalizationSuffixMatch(t *testing.T) {
	// Diff paths are repo-relative; Go cover profiles carry the module prefix.
	changes := []PatchChange{{FilePath: "internal/svc/foo.go", AddedLines: []int{5}}}
	head := map[string][]PatchLine{
		"github.com/acme/proj/internal/svc/foo.go": {{Number: 5, Hits: 2}},
		// A decoy with the same basename but different dir must NOT match.
		"github.com/acme/proj/other/foo.go": {{Number: 5, Hits: 0}},
	}
	pc := BuildPatchCoverage(changes, head, nil, false)
	if pc == nil {
		t.Fatal("expected patch coverage via suffix match")
	}
	if pc.CoveredLines != 1 || pc.UncoveredLines != 0 {
		t.Fatalf("covered/uncovered = %d/%d, want 1/0 (matched svc/foo.go not other/foo.go)", pc.CoveredLines, pc.UncoveredLines)
	}
}

func TestBuildPatchCoverageFilesSortedByUncovered(t *testing.T) {
	changes := []PatchChange{
		{FilePath: "a.go", AddedLines: []int{1}},
		{FilePath: "b.go", AddedLines: []int{1, 2, 3}},
	}
	head := map[string][]PatchLine{
		"a.go": {{Number: 1, Hits: 0}},
		"b.go": {{Number: 1, Hits: 0}, {Number: 2, Hits: 0}, {Number: 3, Hits: 0}},
	}
	pc := BuildPatchCoverage(changes, head, nil, false)
	if pc.Files[0].FilePath != "b.go" {
		t.Fatalf("expected b.go first (most uncovered), got %s", pc.Files[0].FilePath)
	}
}

func TestBuildPatchCoveragePassesHunksThrough(t *testing.T) {
	hunk := "@@ -1,1 +1,2 @@\n a\n+b"
	changes := []PatchChange{{FilePath: "foo.go", AddedLines: []int{2}, Hunks: hunk}}
	head := map[string][]PatchLine{"foo.go": {{Number: 2, Hits: 0}}}
	pc := BuildPatchCoverage(changes, head, nil, false)
	if pc == nil || len(pc.Files) != 1 {
		t.Fatalf("expected one file, got %+v", pc)
	}
	if pc.Files[0].Hunks != hunk {
		t.Fatalf("hunks = %q, want %q", pc.Files[0].Hunks, hunk)
	}
}

func TestBuildPatchCoverageEmptyChanges(t *testing.T) {
	if pc := BuildPatchCoverage(nil, map[string][]PatchLine{}, nil, false); pc != nil {
		t.Fatalf("expected nil for no changes, got %+v", pc)
	}
}
