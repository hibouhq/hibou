package comparison

// ApplyNewCodeLens annotates a coverage diff with new-code stats (ADR-019):
// of the lines this comparison changed, how many are instrumented and how many
// of those are covered.
//
// It reuses the same rules as patch coverage so the two numbers can never
// disagree: only instrumented changed lines are measurable (a changed comment
// or blank line is not), `exclude` globs are honored, and coverage paths are
// reconciled against forge paths exact-first then by longest common suffix.
//
// changed maps a forge (repo-relative) path to the new-side line numbers the
// comparison touched. headLines maps coverage-tool paths to per-line hits.
// A file whose changed lines are all uninstrumented keeps NewLineRate nil —
// callers must render that as "not measurable", never 0%.
func ApplyNewCodeLens(diff *CoverageDiff, changed map[string][]int, headLines map[string][]PatchLine, exclude []string, truncated bool) {
	if diff == nil {
		return
	}
	diff.NewCodeTruncated = truncated
	if len(changed) == 0 {
		return
	}

	index := newCoveragePathIndex(headLines)

	// Coverage-diff rows are keyed by coverage-tool path; the changed set is
	// keyed by forge path. Resolve each changed file once, then attribute its
	// counts to whichever diff row owns that coverage path.
	type counts struct{ lines, covered int }
	byCoveragePath := make(map[string]counts, len(changed))
	totalLines, totalCovered := 0, 0

	for forgePath, lineNumbers := range changed {
		if forgePath == "" || matchesAnyGlob(forgePath, exclude) {
			continue
		}
		hits, ok := index.lookup(forgePath)
		if !ok {
			continue // no coverage for this file: changed lines are unmeasurable
		}
		fileLines, fileCovered := 0, 0
		for _, number := range lineNumbers {
			hitCount, instrumented := hits[number]
			if !instrumented {
				continue
			}
			fileLines++
			if hitCount > 0 {
				fileCovered++
			}
		}
		if fileLines == 0 {
			continue
		}
		totalLines += fileLines
		totalCovered += fileCovered
		resolved := index.resolvePath(forgePath)
		existing := byCoveragePath[resolved]
		existing.lines += fileLines
		existing.covered += fileCovered
		byCoveragePath[resolved] = existing
	}

	for i := range diff.Files {
		got, ok := byCoveragePath[diff.Files[i].FilePath]
		if !ok || got.lines == 0 {
			continue
		}
		diff.Files[i].NewLines = got.lines
		diff.Files[i].NewCovered = got.covered
		rate := float64(got.covered) / float64(got.lines)
		diff.Files[i].NewLineRate = &rate
	}

	diff.NewLines = totalLines
	diff.NewCovered = totalCovered
	if totalLines > 0 {
		rate := float64(totalCovered) / float64(totalLines)
		diff.NewLineRate = &rate
	}
}
