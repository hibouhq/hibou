package server

import (
	"testing"
)

func TestCanonicalCoveragePath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path, slug, want string
	}{
		// Go module paths: cut at the repo-slug segment.
		{"github.com/hibouhq/hibou-sample-project/go/calc.go", "hibou-sample-project", "go/calc.go"},
		{"github.com/hibouhq/hibou-sample-project/go/cmd/app/main.go", "hibou-sample-project", "go/cmd/app/main.go"},
		// Already repo-relative: untouched.
		{"src/calc.ts", "hibou-sample-project", "src/calc.ts"},
		{"./src/calc.ts", "hibou-sample-project", "src/calc.ts"},
		// Java package path has no slug segment: kept as-is.
		{"com/hibou/sample/Calc.java", "hibou-sample-project", "com/hibou/sample/Calc.java"},
		// Slug as the LAST segment must not produce an empty key.
		{"vendor/hibou-sample-project", "hibou-sample-project", "vendor/hibou-sample-project"},
		// Decoy: slug appearing mid-path cuts at the LAST occurrence.
		{"a/hibou-sample-project/b/hibou-sample-project/pkg/f.go", "hibou-sample-project", "pkg/f.go"},
		{"", "hibou-sample-project", ""},
	}
	for _, c := range cases {
		if got := canonicalCoveragePath(c.path, c.slug); got != c.want {
			t.Errorf("canonicalCoveragePath(%q, %q) = %q, want %q", c.path, c.slug, got, c.want)
		}
	}
}

func TestAggregateCoverageReportsUnionsAcrossFormats(t *testing.T) {
	t.Parallel()

	rate := func(v float64) *float64 { return &v }
	reports := []coverageFormatReport{
		{
			Format: "gocover",
			Files: []coverageFileResponse{
				{FilePath: "github.com/o/r/go/calc.go", CanonicalPath: "go/calc.go", LinesValid: 10, LinesCovered: 9, LineRate: rate(0.9)},
			},
		},
		{
			Format: "lcov",
			Files: []coverageFileResponse{
				{FilePath: "src/calc.ts", CanonicalPath: "src/calc.ts", LinesValid: 24, LinesCovered: 22, LineRate: rate(0.917)},
			},
		},
		{
			Format: "jacoco",
			Files: []coverageFileResponse{
				{FilePath: "com/h/s/Calc.java", CanonicalPath: "com/h/s/Calc.java", LinesValid: 11, LinesCovered: 10, BranchesValid: 6, BranchesCovered: 5},
			},
		},
	}

	files, totals := aggregateCoverageReports(reports)
	if len(files) != 3 {
		t.Fatalf("aggregate files = %d, want 3 (union, not primary-only)", len(files))
	}
	if totals.LinesValid != 45 || totals.LinesCovered != 41 {
		t.Fatalf("lines = %d/%d, want 41/45", totals.LinesCovered, totals.LinesValid)
	}
	if totals.BranchesValid != 6 || totals.BranchesCovered != 5 {
		t.Fatalf("branches = %d/%d, want 5/6", totals.BranchesCovered, totals.BranchesValid)
	}
	if totals.LineRate == nil || *totals.LineRate < 0.91 || *totals.LineRate > 0.92 {
		t.Fatalf("line rate = %v, want ~0.911", totals.LineRate)
	}
}

func TestAggregateCoverageReportsCollisionKeepsBetterCovered(t *testing.T) {
	t.Parallel()

	reports := []coverageFormatReport{
		{Format: "gocover", Files: []coverageFileResponse{
			{CanonicalPath: "go/calc.go", LinesValid: 10, LinesCovered: 4},
		}},
		{Format: "lcov", Files: []coverageFileResponse{
			{CanonicalPath: "go/calc.go", LinesValid: 10, LinesCovered: 9},
		}},
	}

	files, totals := aggregateCoverageReports(reports)
	if len(files) != 1 {
		t.Fatalf("files = %d, want 1 (same canonical path must not double-count)", len(files))
	}
	if totals.LinesCovered != 9 {
		t.Fatalf("covered = %d, want 9 (max-wins)", totals.LinesCovered)
	}
}

func TestCoverageReportScope(t *testing.T) {
	t.Parallel()

	if got := coverageReportScope([]coverageFileResponse{
		{CanonicalPath: "ts/src/a.ts"}, {CanonicalPath: "ts/src/b.ts"},
	}); got != "ts" {
		t.Fatalf("scope = %q, want ts", got)
	}
	if got := coverageReportScope([]coverageFileResponse{
		{CanonicalPath: "ts/a.ts"}, {CanonicalPath: "rust/b.rs"},
	}); got != "" {
		t.Fatalf("scope = %q, want empty for mixed roots", got)
	}
	if got := coverageReportScope([]coverageFileResponse{{CanonicalPath: "single.go"}}); got != "" {
		t.Fatalf("scope = %q, want empty for root-level file", got)
	}
}
