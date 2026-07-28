package coverage

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Report struct {
	Format          string
	LineRate        float64
	BranchRate      float64
	LinesValid      int
	LinesCovered    int
	BranchesValid   int
	BranchesCovered int
	Files           []FileCoverage
}

type FileCoverage struct {
	Path            string
	LineRate        float64
	BranchRate      float64
	LinesValid      int
	LinesCovered    int
	BranchesValid   int
	BranchesCovered int
	// Lines holds per-line hit counts for instrumented lines. It powers
	// line-level patch coverage (which changed lines a PR left untested).
	// A line with Hits == 0 is instrumented-but-uncovered; absent lines are
	// not instrumented. May be empty for summary-only reports.
	Lines []LineCoverage
}

// LineCoverage is the hit count for a single instrumented source line, plus
// branch counters when the format reports them (JaCoCo mb/cb, LCOV BRDA,
// Cobertura condition-coverage). BranchesValid == 0 means the line has no
// branch — not that branches are unknown; formats without branch data
// (gocover) simply never set them. A line with Hits > 0 and
// BranchesCovered < BranchesValid is PARTIALLY covered: executed, but some
// conditions never took both outcomes.
type LineCoverage struct {
	Number          int
	Hits            int
	BranchesCovered int
	BranchesValid   int
}

func Parse(content []byte, format string) (*Report, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, errors.New("empty coverage report")
	}

	normalized := strings.ToLower(strings.TrimSpace(format))

	var (
		report *Report
		err    error
	)

	switch normalized {
	case "cobertura":
		report, err = parseCobertura(content)
	case "lcov":
		report, err = parseLCOV(content)
	case "gocover":
		report, err = parseGoCover(content)
	case "jacoco":
		report, err = parseJaCoCo(content)
	case "clover":
		return nil, errors.New("clover coverage parsing not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported coverage format: %s", format)
	}
	if err != nil {
		return nil, err
	}

	report.Format = normalized
	return report, nil
}

func rate(covered, valid int) float64 {
	if valid <= 0 {
		return 0
	}
	return float64(covered) / float64(valid)
}

func sortFiles(files []FileCoverage) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
}

// finalizeLines dedupes per-line records by line number (keeping the maximum
// hit count seen, so a line executed by any block/report counts as covered;
// branch counters take the record with the most branches known, preferring
// higher coverage at equal width) and returns them sorted by line number.
// Parsers accumulate raw line records — possibly with duplicates across merged
// classes, records, or blocks — and call this once per file before emitting
// the report.
func finalizeLines(lines []LineCoverage) []LineCoverage {
	if len(lines) == 0 {
		return nil
	}
	merged := make(map[int]LineCoverage, len(lines))
	for _, line := range lines {
		if line.Number <= 0 {
			continue
		}
		existing, ok := merged[line.Number]
		if !ok {
			merged[line.Number] = line
			continue
		}
		if line.Hits > existing.Hits {
			existing.Hits = line.Hits
		}
		if line.BranchesValid > existing.BranchesValid ||
			(line.BranchesValid == existing.BranchesValid && line.BranchesCovered > existing.BranchesCovered) {
			existing.BranchesValid = line.BranchesValid
			existing.BranchesCovered = line.BranchesCovered
		}
		merged[line.Number] = existing
	}
	if len(merged) == 0 {
		return nil
	}
	result := make([]LineCoverage, 0, len(merged))
	for _, line := range merged {
		result = append(result, line)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Number < result[j].Number
	})
	return result
}
