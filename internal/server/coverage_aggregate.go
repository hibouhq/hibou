package server

import (
	"sort"
	"strings"
)

// Coverage tools emit paths at different roots: Go cover profiles carry the
// module path, JaCoCo the package path, lcov a source-relative path. Anything
// that has to line files up -- aggregating reports, diffing two snapshots,
// fetching a blob from the forge -- needs one key per file, so derive a
// repo-root-relative one and keep the raw path for display.
func canonicalCoveragePath(path, repoSlug string) string {
	trimmed := strings.TrimSpace(path)
	trimmed = strings.TrimPrefix(trimmed, "./")
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return ""
	}

	// Go module paths look like <host>/<org>/<repo>/<pkg>/file.go. Cut at the last
	// segment matching the repository slug so only the in-repo part survives.
	if slug := strings.TrimSpace(repoSlug); slug != "" {
		segments := strings.Split(trimmed, "/")
		for i := len(segments) - 1; i >= 0; i-- {
			if !strings.EqualFold(segments[i], slug) {
				continue
			}
			if rest := strings.Join(segments[i+1:], "/"); rest != "" {
				return rest
			}
			break
		}
	}
	return trimmed
}

// coverageReportScope labels a report by the directory its files share, so two
// reports in the same format stay distinguishable ("lcov · ts" vs "lcov · rust").
// Empty when the files share no single root.
func coverageReportScope(files []coverageFileResponse) string {
	root := ""
	for _, file := range files {
		head := file.CanonicalPath
		if head == "" {
			head = file.FilePath
		}
		if idx := strings.Index(head, "/"); idx > 0 {
			head = head[:idx]
		} else {
			return ""
		}
		if root == "" {
			root = head
			continue
		}
		if root != head {
			return ""
		}
	}
	return root
}

// aggregateCoverageReports unions every report into one project-wide view.
//
// Picking a single "primary" report meant a repo with four languages only ever
// showed one of them, and which one won depended on whichever happened to have
// the most instrumented lines that run -- so the same PR could compare
// TypeScript against Go and report a large fake regression.
//
// Files are keyed by canonical path. A collision means two tools measured the
// same file, so the better-covered row wins rather than being counted twice.
// Totals are recomputed from the surviving rows so the headline number and the
// file table can never disagree.
func aggregateCoverageReports(reports []coverageFormatReport) ([]coverageFileResponse, coverageTotals) {
	best := make(map[string]coverageFileResponse)
	for _, report := range reports {
		for _, file := range report.Files {
			key := file.CanonicalPath
			if key == "" {
				key = file.FilePath
			}
			existing, seen := best[key]
			if !seen || file.LinesCovered > existing.LinesCovered {
				best[key] = file
			}
		}
	}

	files := make([]coverageFileResponse, 0, len(best))
	var totals coverageTotals
	for _, file := range best {
		files = append(files, file)
		totals.LinesValid += file.LinesValid
		totals.LinesCovered += file.LinesCovered
		totals.BranchesValid += file.BranchesValid
		totals.BranchesCovered += file.BranchesCovered
	}
	sort.Slice(files, func(i, j int) bool {
		return coverageFileSortKey(files[i]) < coverageFileSortKey(files[j])
	})

	totals.LineRate = ratio(totals.LinesCovered, totals.LinesValid)
	totals.BranchRate = ratio(totals.BranchesCovered, totals.BranchesValid)
	return files, totals
}

type coverageTotals struct {
	LineRate        *float64
	BranchRate      *float64
	LinesValid      int
	LinesCovered    int
	BranchesValid   int
	BranchesCovered int
}

func coverageFileSortKey(file coverageFileResponse) string {
	if file.CanonicalPath != "" {
		return file.CanonicalPath
	}
	return file.FilePath
}

func ratio(covered, valid int) *float64 {
	if valid <= 0 {
		return nil
	}
	rate := float64(covered) / float64(valid)
	return &rate
}
