// Package comparison computes pure, presentation-ready diffs between two
// repository snapshots for quality signals that are not security findings:
// code coverage and test results. It intentionally has no database or HTTP
// dependencies so the diff logic stays unit-testable in isolation.
package comparison

import "sort"

// CoverageInput is the coverage data for a single snapshot, already reduced to
// the primary report's totals plus its per-file rows.
type CoverageInput struct {
	HasData         bool
	Format          string
	LineRate        *float64
	BranchRate      *float64
	LinesValid      int
	LinesCovered    int
	BranchesValid   int
	BranchesCovered int
	Files           []CoverageFileInput
}

// CoverageFileInput is one file's coverage within a snapshot.
type CoverageFileInput struct {
	FilePath     string
	LineRate     *float64
	LinesValid   int
	LinesCovered int
}

// CoverageTotals is the snapshot-level coverage summary used on each side of a diff.
type CoverageTotals struct {
	Format          string   `json:"format"`
	LineRate        *float64 `json:"line_rate"`
	BranchRate      *float64 `json:"branch_rate"`
	LinesValid      int      `json:"lines_valid"`
	LinesCovered    int      `json:"lines_covered"`
	BranchesValid   int      `json:"branches_valid"`
	BranchesCovered int      `json:"branches_covered"`
}

// CoverageFileDelta is the per-file coverage change between base and head.
type CoverageFileDelta struct {
	FilePath         string   `json:"file_path"`
	Change           string   `json:"change"` // added|removed|improved|regressed
	BaseLineRate     *float64 `json:"base_line_rate"`
	HeadLineRate     *float64 `json:"head_line_rate"`
	LineRateDelta    *float64 `json:"line_rate_delta"`
	BaseLinesCovered int      `json:"base_lines_covered"`
	HeadLinesCovered int      `json:"head_lines_covered"`
	BaseLinesValid   int      `json:"base_lines_valid"`
	HeadLinesValid   int      `json:"head_lines_valid"`
}

// CoverageDiff is the full coverage comparison between two snapshots.
type CoverageDiff struct {
	Base            *CoverageTotals     `json:"base"`
	Head            *CoverageTotals     `json:"head"`
	LineRateDelta   *float64            `json:"line_rate_delta"`
	BranchRateDelta *float64            `json:"branch_rate_delta"`
	Files           []CoverageFileDelta `json:"files"`
	UnchangedFiles  int                 `json:"unchanged_files"`
}

// coverageRateEpsilon is the smallest line-rate change considered meaningful.
// Below it, a file is treated as unchanged. Rates are 0..1 fractions.
const coverageRateEpsilon = 0.0001

// BuildCoverageDiff compares two snapshots' primary coverage data. It returns
// nil only when neither side has coverage data, letting callers omit the
// section entirely.
func BuildCoverageDiff(base, head CoverageInput) *CoverageDiff {
	if !base.HasData && !head.HasData {
		return nil
	}

	diff := &CoverageDiff{Files: []CoverageFileDelta{}}
	if base.HasData {
		diff.Base = coverageTotalsFromInput(base)
	}
	if head.HasData {
		diff.Head = coverageTotalsFromInput(head)
	}
	diff.LineRateDelta = ratePtrDelta(base.LineRate, head.LineRate)
	diff.BranchRateDelta = ratePtrDelta(base.BranchRate, head.BranchRate)

	baseFiles := indexCoverageFiles(base.Files)
	headFiles := indexCoverageFiles(head.Files)

	for path, headFile := range headFiles {
		baseFile, ok := baseFiles[path]
		if !ok {
			diff.Files = append(diff.Files, coverageFileDelta("added", CoverageFileInput{}, headFile, false))
			continue
		}
		delta := lineRateDelta(baseFile, headFile)
		switch {
		case delta > coverageRateEpsilon:
			diff.Files = append(diff.Files, coverageFileDelta("improved", baseFile, headFile, true))
		case delta < -coverageRateEpsilon:
			diff.Files = append(diff.Files, coverageFileDelta("regressed", baseFile, headFile, true))
		default:
			diff.UnchangedFiles++
		}
	}
	for path, baseFile := range baseFiles {
		if _, ok := headFiles[path]; ok {
			continue
		}
		diff.Files = append(diff.Files, coverageFileDelta("removed", baseFile, CoverageFileInput{}, false))
	}

	sortCoverageFileDeltas(diff.Files)
	return diff
}

func coverageTotalsFromInput(in CoverageInput) *CoverageTotals {
	return &CoverageTotals{
		Format:          in.Format,
		LineRate:        in.LineRate,
		BranchRate:      in.BranchRate,
		LinesValid:      in.LinesValid,
		LinesCovered:    in.LinesCovered,
		BranchesValid:   in.BranchesValid,
		BranchesCovered: in.BranchesCovered,
	}
}

func indexCoverageFiles(files []CoverageFileInput) map[string]CoverageFileInput {
	index := make(map[string]CoverageFileInput, len(files))
	for _, file := range files {
		index[file.FilePath] = file
	}
	return index
}

func lineRateDelta(base, head CoverageFileInput) float64 {
	return effectiveLineRate(head) - effectiveLineRate(base)
}

// effectiveLineRate prefers the stored rate but falls back to covered/valid so
// files without a precomputed rate still compare correctly.
func effectiveLineRate(file CoverageFileInput) float64 {
	if file.LineRate != nil {
		return *file.LineRate
	}
	if file.LinesValid > 0 {
		return float64(file.LinesCovered) / float64(file.LinesValid)
	}
	return 0
}

func coverageFileDelta(change string, base, head CoverageFileInput, bothSides bool) CoverageFileDelta {
	delta := CoverageFileDelta{
		Change:           change,
		BaseLineRate:     base.LineRate,
		HeadLineRate:     head.LineRate,
		BaseLinesCovered: base.LinesCovered,
		HeadLinesCovered: head.LinesCovered,
		BaseLinesValid:   base.LinesValid,
		HeadLinesValid:   head.LinesValid,
	}
	if change == "added" {
		delta.FilePath = head.FilePath
	} else {
		delta.FilePath = base.FilePath
	}
	if delta.FilePath == "" {
		delta.FilePath = head.FilePath
	}
	if bothSides {
		d := effectiveLineRate(head) - effectiveLineRate(base)
		delta.LineRateDelta = &d
	}
	return delta
}

func sortCoverageFileDeltas(files []CoverageFileDelta) {
	sort.SliceStable(files, func(i, j int) bool {
		left, right := files[i], files[j]
		if coverageChangeRank(left.Change) != coverageChangeRank(right.Change) {
			return coverageChangeRank(left.Change) < coverageChangeRank(right.Change)
		}
		// Within a bucket, surface the largest movements first.
		li, lj := absRate(left.LineRateDelta), absRate(right.LineRateDelta)
		if li != lj {
			return li > lj
		}
		return left.FilePath < right.FilePath
	})
}

func coverageChangeRank(change string) int {
	switch change {
	case "regressed":
		return 0
	case "removed":
		return 1
	case "improved":
		return 2
	case "added":
		return 3
	default:
		return 4
	}
}

func absRate(value *float64) float64 {
	if value == nil {
		return 0
	}
	if *value < 0 {
		return -*value
	}
	return *value
}

func ratePtrDelta(base, head *float64) *float64 {
	if base == nil || head == nil {
		return nil
	}
	d := *head - *base
	return &d
}
