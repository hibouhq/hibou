package comparison

import "testing"

func floatPtr(v float64) *float64 { return &v }

func findCoverageFile(files []CoverageFileDelta, path string) (CoverageFileDelta, bool) {
	for _, f := range files {
		if f.FilePath == path {
			return f, true
		}
	}
	return CoverageFileDelta{}, false
}

func TestBuildCoverageDiffNilWhenNoData(t *testing.T) {
	if diff := BuildCoverageDiff(CoverageInput{}, CoverageInput{}); diff != nil {
		t.Fatalf("expected nil diff when neither side has data, got %+v", diff)
	}
}

func TestBuildCoverageDiffClassifiesFiles(t *testing.T) {
	base := CoverageInput{
		HasData:      true,
		LineRate:     floatPtr(0.50),
		LinesValid:   100,
		LinesCovered: 50,
		Files: []CoverageFileInput{
			{FilePath: "a.go", LineRate: floatPtr(0.50), LinesValid: 10, LinesCovered: 5},
			{FilePath: "b.go", LineRate: floatPtr(0.80), LinesValid: 10, LinesCovered: 8},
			{FilePath: "gone.go", LineRate: floatPtr(0.90), LinesValid: 10, LinesCovered: 9},
			{FilePath: "steady.go", LineRate: floatPtr(0.70), LinesValid: 10, LinesCovered: 7},
		},
	}
	head := CoverageInput{
		HasData:      true,
		LineRate:     floatPtr(0.65),
		LinesValid:   110,
		LinesCovered: 71,
		Files: []CoverageFileInput{
			{FilePath: "a.go", LineRate: floatPtr(0.90), LinesValid: 10, LinesCovered: 9},      // improved
			{FilePath: "b.go", LineRate: floatPtr(0.40), LinesValid: 10, LinesCovered: 4},      // regressed
			{FilePath: "new.go", LineRate: floatPtr(0.30), LinesValid: 10, LinesCovered: 3},    // added
			{FilePath: "steady.go", LineRate: floatPtr(0.70), LinesValid: 10, LinesCovered: 7}, // unchanged
		},
	}

	diff := BuildCoverageDiff(base, head)
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if diff.UnchangedFiles != 1 {
		t.Fatalf("expected 1 unchanged file, got %d", diff.UnchangedFiles)
	}
	if diff.LineRateDelta == nil || *diff.LineRateDelta < 0.149 || *diff.LineRateDelta > 0.151 {
		t.Fatalf("expected overall line rate delta ~0.15, got %v", diff.LineRateDelta)
	}

	cases := map[string]string{"a.go": "improved", "b.go": "regressed", "new.go": "added", "gone.go": "removed"}
	for path, want := range cases {
		got, ok := findCoverageFile(diff.Files, path)
		if !ok {
			t.Fatalf("expected file %s in diff", path)
		}
		if got.Change != want {
			t.Fatalf("file %s: expected change %s, got %s", path, want, got.Change)
		}
	}
	if _, ok := findCoverageFile(diff.Files, "steady.go"); ok {
		t.Fatal("unchanged file should not appear in files list")
	}
}

func TestBuildCoverageDiffOneSidedTotals(t *testing.T) {
	head := CoverageInput{HasData: true, LineRate: floatPtr(0.5), LinesValid: 10, LinesCovered: 5}
	diff := BuildCoverageDiff(CoverageInput{}, head)
	if diff == nil || diff.Base != nil || diff.Head == nil {
		t.Fatalf("expected head-only diff, got %+v", diff)
	}
	if diff.LineRateDelta != nil {
		t.Fatalf("expected nil line rate delta when base missing, got %v", *diff.LineRateDelta)
	}
}

func TestSignificantTiming(t *testing.T) {
	tests := []struct {
		name string
		base float64
		head float64
		want timingDirection
	}{
		{"below abs floor", 0.10, 0.12, timingNone},
		{"proportional slower", 0.20, 0.40, timingSlower},
		{"proportional faster", 0.40, 0.18, timingFaster},
		{"big abs but small relative", 1.00, 1.10, timingNone},
		{"newly expensive from zero", 0.0, 0.25, timingSlower},
		{"small base small head", 0.001, 0.04, timingNone},
		{"newly expensive just under floor", 0.0, 0.19, timingNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := significantTiming(tt.base, tt.head); got != tt.want {
				t.Fatalf("significantTiming(%v,%v)=%v want %v", tt.base, tt.head, got, tt.want)
			}
		})
	}
}

func TestBuildTestDiffClassification(t *testing.T) {
	base := TestReportInput{
		HasData:         true,
		Format:          "junit",
		Total:           4,
		Passed:          3,
		Skipped:         1,
		DurationSeconds: 1.0,
		Cases: []TestCaseInput{
			{Suite: "s", Classname: "c", Name: "Skipped", Status: "passed", DurationSeconds: 0.10},
			{Suite: "s", Classname: "c", Name: "Slow", Status: "passed", DurationSeconds: 0.20},
			{Suite: "s", Classname: "c", Name: "Steady", Status: "passed", DurationSeconds: 0.10},
			{Suite: "s", Classname: "c", Name: "Removed", Status: "passed", DurationSeconds: 0.10},
		},
	}
	head := TestReportInput{
		HasData:         true,
		Format:          "junit",
		Total:           4,
		Passed:          2,
		Skipped:         1,
		Failed:          1,
		DurationSeconds: 1.6,
		Cases: []TestCaseInput{
			{Suite: "s", Classname: "c", Name: "Skipped", Status: "skipped", DurationSeconds: 0.0},
			{Suite: "s", Classname: "c", Name: "Slow", Status: "passed", DurationSeconds: 0.50},   // slower
			{Suite: "s", Classname: "c", Name: "Steady", Status: "passed", DurationSeconds: 0.10}, // unchanged
			{Suite: "s", Classname: "c", Name: "Added", Status: "failed", DurationSeconds: 0.30},
		},
	}

	diff := BuildTestDiff(base, head)
	if diff == nil {
		t.Fatal("expected non-nil diff")
	}
	if len(diff.Added) != 1 || diff.Added[0].Name != "Added" {
		t.Fatalf("expected 1 added case 'Added', got %+v", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Name != "Removed" {
		t.Fatalf("expected 1 removed case 'Removed', got %+v", diff.Removed)
	}
	if len(diff.StatusChanged) != 1 || diff.StatusChanged[0].Name != "Skipped" {
		t.Fatalf("expected 1 status-changed case 'Skipped', got %+v", diff.StatusChanged)
	}
	if diff.StatusChanged[0].BaseStatus != "passed" || diff.StatusChanged[0].HeadStatus != "skipped" {
		t.Fatalf("unexpected status transition: %+v", diff.StatusChanged[0])
	}
	if len(diff.Slower) != 1 || diff.Slower[0].Name != "Slow" {
		t.Fatalf("expected 1 slower case 'Slow', got %+v", diff.Slower)
	}
	if diff.Unchanged != 1 {
		t.Fatalf("expected 1 unchanged case, got %d", diff.Unchanged)
	}
	if diff.DurationDeltaSeconds < 0.59 || diff.DurationDeltaSeconds > 0.61 {
		t.Fatalf("expected duration delta ~0.6, got %v", diff.DurationDeltaSeconds)
	}
}

func TestBuildTestDiffNilWhenNoData(t *testing.T) {
	if diff := BuildTestDiff(TestReportInput{}, TestReportInput{}); diff != nil {
		t.Fatalf("expected nil diff, got %+v", diff)
	}
}

func TestBuildTestDiffStatusChangePriorityOverTiming(t *testing.T) {
	base := TestReportInput{HasData: true, Cases: []TestCaseInput{
		{Suite: "s", Classname: "c", Name: "T", Status: "passed", DurationSeconds: 0.10},
	}}
	head := TestReportInput{HasData: true, Cases: []TestCaseInput{
		{Suite: "s", Classname: "c", Name: "T", Status: "failed", DurationSeconds: 0.90},
	}}
	diff := BuildTestDiff(base, head)
	if len(diff.StatusChanged) != 1 || len(diff.Slower) != 0 {
		t.Fatalf("status change should take priority over timing, got statusChanged=%d slower=%d", len(diff.StatusChanged), len(diff.Slower))
	}
}
