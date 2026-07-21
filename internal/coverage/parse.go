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

// LineCoverage is the hit count for a single instrumented source line.
type LineCoverage struct {
	Number int
	Hits   int
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
// hit count seen, so a line executed by any block/report counts as covered)
// and returns them sorted by line number. Parsers accumulate raw line records
// — possibly with duplicates across merged classes, records, or blocks — and
// call this once per file before emitting the report.
func finalizeLines(lines []LineCoverage) []LineCoverage {
	if len(lines) == 0 {
		return nil
	}
	maxHits := make(map[int]int, len(lines))
	for _, line := range lines {
		if line.Number <= 0 {
			continue
		}
		if existing, ok := maxHits[line.Number]; !ok || line.Hits > existing {
			maxHits[line.Number] = line.Hits
		}
	}
	if len(maxHits) == 0 {
		return nil
	}
	result := make([]LineCoverage, 0, len(maxHits))
	for number, hits := range maxHits {
		result = append(result, LineCoverage{Number: number, Hits: hits})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Number < result[j].Number
	})
	return result
}
