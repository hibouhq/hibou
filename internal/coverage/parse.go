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
