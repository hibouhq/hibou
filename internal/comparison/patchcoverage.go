package comparison

import (
	"path"
	"sort"
	"strings"
)

// PatchChange is one changed file in a pull request and the new-side line
// numbers a change added or modified. It mirrors forge.PatchFile but is
// redeclared here so the comparison package stays free of forge/HTTP deps
// (ADR-005). The server maps forge output into these before calling.
type PatchChange struct {
	FilePath   string
	AddedLines []int
	// Hunks is the raw unified-diff text for this file, passed straight through
	// to the result so the client can render an annotated diff. The comparison
	// package treats it as opaque.
	Hunks string
}

// PatchLine is one instrumented source line's hit count on the head snapshot.
type PatchLine struct {
	Number int
	Hits   int
}

// PatchFileCoverage is the patch-coverage result for a single changed file.
type PatchFileCoverage struct {
	FilePath       string `json:"file_path"`
	CoveredLines   int    `json:"covered_lines"`
	UncoveredLines int    `json:"uncovered_lines"`
	// Rate is covered / (covered + uncovered) for this file's changed,
	// instrumented lines; nil when the change touched no instrumented lines.
	Rate *float64 `json:"rate"`
	// CoveredLineNumbers / UncoveredLineNumbers are the changed, instrumented
	// line numbers by outcome, sorted ascending — the UI tints these on the
	// diff. UncoveredLineNumbers is the reviewer's punch-list.
	CoveredLineNumbers   []int `json:"covered_line_numbers"`
	UncoveredLineNumbers []int `json:"uncovered_line_numbers"`
	// Hunks is the raw unified-diff text for this file (forge-provided), so the
	// client renders the annotated diff by tinting each added line against the
	// covered/uncovered sets above. Empty when the forge supplied no patch.
	Hunks string `json:"hunks,omitempty"`
	// Full-file instrumented line numbers by outcome. Head sets use new-side
	// numbering, base sets old-side; together they let the diff distinguish a
	// line that is plain covered/uncovered from one whose coverage state the PR
	// changed (gained or lost).
	HeadCoveredLines   []int `json:"head_covered_lines,omitempty"`
	HeadUncoveredLines []int `json:"head_uncovered_lines,omitempty"`
	BaseCoveredLines   []int `json:"base_covered_lines,omitempty"`
	BaseUncoveredLines []int `json:"base_uncovered_lines,omitempty"`
}

// PatchCoverage is the repository-wide patch (diff) coverage: of the lines a
// PR added or modified that the test suite can measure, the fraction it
// executes. This is the headline "did this change add untested code?" signal.
type PatchCoverage struct {
	CoveredLines   int `json:"covered_lines"`
	UncoveredLines int `json:"uncovered_lines"`
	// Rate is covered / (covered + uncovered) across all changed, instrumented
	// lines; nil when no changed line was instrumented (e.g. a docs-only PR),
	// letting the UI show "—" rather than a misleading 0% or 100%.
	Rate *float64 `json:"rate"`
	// Truncated propagates a forge-side file-list cap so a partial number is
	// never presented as complete.
	Truncated bool                `json:"truncated"`
	Files     []PatchFileCoverage `json:"files"`
}

// BuildPatchCoverage intersects a PR's changed lines with the head snapshot's
// per-line coverage. Only *instrumented* changed lines count: an added line
// with no coverage record (blank line, comment, or a file with no coverage at
// all) is not measurable and is excluded from the ratio. Files matching an
// exclude glob are skipped entirely. Returns nil when there is nothing to
// report (no changes, or none intersect coverage), so the caller can omit the
// section.
func BuildPatchCoverage(changes []PatchChange, headLines, baseLines map[string][]PatchLine, exclude []string, truncated bool) *PatchCoverage {
	if len(changes) == 0 {
		return nil
	}

	index := newCoveragePathIndex(headLines)
	baseIndex := newCoveragePathIndex(baseLines)
	result := &PatchCoverage{Truncated: truncated, Files: []PatchFileCoverage{}}

	for _, change := range changes {
		if change.FilePath == "" || matchesAnyGlob(change.FilePath, exclude) {
			continue
		}
		lineHits, ok := index.lookup(change.FilePath)
		if !ok {
			continue // file has no coverage data; changed lines are unmeasurable
		}
		fileCov := patchCoverageForFile(change, lineHits)
		if fileCov == nil {
			continue // no changed line was instrumented in this file
		}
		fileCov.HeadCoveredLines, fileCov.HeadUncoveredLines = splitByOutcome(lineHits)
		if baseHits, ok := baseIndex.lookup(change.FilePath); ok {
			fileCov.BaseCoveredLines, fileCov.BaseUncoveredLines = splitByOutcome(baseHits)
		}
		result.CoveredLines += fileCov.CoveredLines
		result.UncoveredLines += fileCov.UncoveredLines
		result.Files = append(result.Files, *fileCov)
	}

	if len(result.Files) == 0 {
		return nil
	}
	result.Rate = ratio(result.CoveredLines, result.UncoveredLines)
	sortPatchFiles(result.Files)
	return result
}

// splitByOutcome partitions a file's instrumented lines into covered and
// uncovered line-number lists, sorted ascending.
func splitByOutcome(lineHits map[int]int) (covered, uncovered []int) {
	for number, hits := range lineHits {
		if hits > 0 {
			covered = append(covered, number)
		} else {
			uncovered = append(uncovered, number)
		}
	}
	sort.Ints(covered)
	sort.Ints(uncovered)
	return covered, uncovered
}

// patchCoverageForFile classifies a single file's changed lines against its
// per-line hits. Returns nil when no changed line is instrumented.
func patchCoverageForFile(change PatchChange, lineHits map[int]int) *PatchFileCoverage {
	fileCov := &PatchFileCoverage{FilePath: change.FilePath, Hunks: change.Hunks}
	for _, line := range change.AddedLines {
		hits, instrumented := lineHits[line]
		if !instrumented {
			continue
		}
		if hits > 0 {
			fileCov.CoveredLines++
			fileCov.CoveredLineNumbers = append(fileCov.CoveredLineNumbers, line)
		} else {
			fileCov.UncoveredLines++
			fileCov.UncoveredLineNumbers = append(fileCov.UncoveredLineNumbers, line)
		}
	}
	if fileCov.CoveredLines == 0 && fileCov.UncoveredLines == 0 {
		return nil
	}
	sort.Ints(fileCov.CoveredLineNumbers)
	sort.Ints(fileCov.UncoveredLineNumbers)
	fileCov.Rate = ratio(fileCov.CoveredLines, fileCov.UncoveredLines)
	return fileCov
}

// coveragePathIndex resolves a forge diff path (repo-root-relative) to a
// coverage file's per-line hits. Coverage tools emit paths at different roots
// (Go cover profiles carry the full module path; JaCoCo carries the package
// path), so exact match is tried first, then the longest common-suffix match.
type coveragePathIndex struct {
	byPath map[string]map[int]int
}

func newCoveragePathIndex(headLines map[string][]PatchLine) *coveragePathIndex {
	byPath := make(map[string]map[int]int, len(headLines))
	for filePath, lines := range headLines {
		hits := make(map[int]int, len(lines))
		for _, line := range lines {
			// Keep the covered reading if a line appears twice.
			if existing, ok := hits[line.Number]; !ok || line.Hits > existing {
				hits[line.Number] = line.Hits
			}
		}
		byPath[normalizePath(filePath)] = hits
	}
	return &coveragePathIndex{byPath: byPath}
}

// lookup finds the coverage hits for a diff path. Exact normalized match wins;
// otherwise the coverage path with the longest path-segment suffix shared with
// the diff path is used, which reconciles module/package-prefixed coverage
// paths with repo-relative diff paths without cross-matching unrelated files.
func (c *coveragePathIndex) lookup(diffPath string) (map[int]int, bool) {
	coveragePath, ok := c.match(diffPath)
	if !ok {
		return nil, false
	}
	return c.byPath[coveragePath], true
}

// resolvePath returns the coverage-tool path a forge path maps to, or the
// normalized input when nothing matches. Callers that must key results by
// coverage path (the new-code lens joins onto coverage-diff rows) use this so
// resolution stays identical to lookup's.
func (c *coveragePathIndex) resolvePath(diffPath string) string {
	if coveragePath, ok := c.match(diffPath); ok {
		return coveragePath
	}
	return normalizePath(diffPath)
}

func (c *coveragePathIndex) match(diffPath string) (string, bool) {
	normalized := normalizePath(diffPath)
	if _, ok := c.byPath[normalized]; ok {
		return normalized, true
	}
	bestScore := 0
	best := ""
	for coveragePath := range c.byPath {
		score := commonSuffixSegments(coveragePath, normalized)
		if score > bestScore {
			bestScore = score
			best = coveragePath
		}
	}
	if bestScore == 0 {
		return "", false
	}
	return best, true
}

// commonSuffixSegments counts how many trailing path segments two paths share.
// A shared basename scores 1; "a/b/c.go" vs "x/b/c.go" scores 2. Zero means no
// shared suffix (and thus no match).
func commonSuffixSegments(a, b string) int {
	as := strings.Split(a, "/")
	bs := strings.Split(b, "/")
	count := 0
	for i, j := len(as)-1, len(bs)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if as[i] != bs[j] || as[i] == "" {
			break
		}
		count++
	}
	return count
}

func normalizePath(p string) string {
	return strings.TrimPrefix(path.Clean(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")), "./")
}

// matchesAnyGlob reports whether filePath matches any of the exclude globs,
// testing both the full path and its basename so patterns like "*_test.go"
// work regardless of directory depth.
func matchesAnyGlob(filePath string, globs []string) bool {
	if len(globs) == 0 {
		return false
	}
	normalized := normalizePath(filePath)
	base := path.Base(normalized)
	for _, glob := range globs {
		glob = strings.TrimSpace(glob)
		if glob == "" {
			continue
		}
		if ok, _ := path.Match(glob, normalized); ok {
			return true
		}
		if ok, _ := path.Match(glob, base); ok {
			return true
		}
		// Support "dir/**" recursive prefix excludes.
		if strings.HasSuffix(glob, "/**") {
			prefix := strings.TrimSuffix(glob, "/**")
			if normalized == prefix || strings.HasPrefix(normalized, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func sortPatchFiles(files []PatchFileCoverage) {
	sort.SliceStable(files, func(i, j int) bool {
		// Files with the most uncovered new lines first — that is where a
		// reviewer's attention is most needed.
		if files[i].UncoveredLines != files[j].UncoveredLines {
			return files[i].UncoveredLines > files[j].UncoveredLines
		}
		return files[i].FilePath < files[j].FilePath
	})
}

func ratio(covered, uncovered int) *float64 {
	total := covered + uncovered
	if total <= 0 {
		return nil
	}
	r := float64(covered) / float64(total)
	return &r
}
