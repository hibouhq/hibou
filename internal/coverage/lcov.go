package coverage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func parseLCOV(content []byte) (*Report, error) {
	type lcovRecord struct {
		file                   FileCoverage
		hasLinesValid          bool
		hasLinesCovered        bool
		hasBranchesValid       bool
		hasBranchesCovered     bool
		derivedLinesValid      int
		derivedLinesCovered    int
		derivedBranchesValid   int
		derivedBranchesCovered int
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	filesByPath := make(map[string]*FileCoverage)
	current := &lcovRecord{}

	flush := func() {
		path := strings.TrimSpace(current.file.Path)
		if path == "" {
			current = &lcovRecord{}
			return
		}
		if !current.hasLinesValid {
			current.file.LinesValid = current.derivedLinesValid
		}
		if !current.hasLinesCovered {
			current.file.LinesCovered = current.derivedLinesCovered
		}
		if !current.hasBranchesValid {
			current.file.BranchesValid = current.derivedBranchesValid
		}
		if !current.hasBranchesCovered {
			current.file.BranchesCovered = current.derivedBranchesCovered
		}

		target := filesByPath[path]
		if target == nil {
			target = &FileCoverage{Path: path}
			filesByPath[path] = target
		}
		target.LinesValid += current.file.LinesValid
		target.LinesCovered += current.file.LinesCovered
		target.BranchesValid += current.file.BranchesValid
		target.BranchesCovered += current.file.BranchesCovered
		current = &lcovRecord{}
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "SF:"):
			flush()
			current.file.Path = strings.TrimSpace(strings.TrimPrefix(line, "SF:"))
		case strings.HasPrefix(line, "LF:"):
			value, ok := parseOptionalInt(strings.TrimPrefix(line, "LF:"))
			if !ok {
				return nil, fmt.Errorf("invalid LF line: %s", line)
			}
			current.file.LinesValid = value
			current.hasLinesValid = true
		case strings.HasPrefix(line, "LH:"):
			value, ok := parseOptionalInt(strings.TrimPrefix(line, "LH:"))
			if !ok {
				return nil, fmt.Errorf("invalid LH line: %s", line)
			}
			current.file.LinesCovered = value
			current.hasLinesCovered = true
		case strings.HasPrefix(line, "BRF:"):
			value, ok := parseOptionalInt(strings.TrimPrefix(line, "BRF:"))
			if !ok {
				return nil, fmt.Errorf("invalid BRF line: %s", line)
			}
			current.file.BranchesValid = value
			current.hasBranchesValid = true
		case strings.HasPrefix(line, "BRH:"):
			value, ok := parseOptionalInt(strings.TrimPrefix(line, "BRH:"))
			if !ok {
				return nil, fmt.Errorf("invalid BRH line: %s", line)
			}
			current.file.BranchesCovered = value
			current.hasBranchesCovered = true
		case strings.HasPrefix(line, "DA:"):
			parts := strings.Split(strings.TrimPrefix(line, "DA:"), ",")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid DA line: %s", line)
			}
			count, ok := parseOptionalInt(parts[1])
			if !ok {
				return nil, fmt.Errorf("invalid DA line: %s", line)
			}
			current.derivedLinesValid++
			if count > 0 {
				current.derivedLinesCovered++
			}
		case strings.HasPrefix(line, "BRDA:"):
			parts := strings.Split(strings.TrimPrefix(line, "BRDA:"), ",")
			if len(parts) != 4 {
				return nil, fmt.Errorf("invalid BRDA line: %s", line)
			}
			current.derivedBranchesValid++
			taken := strings.TrimSpace(parts[3])
			if taken == "-" {
				continue
			}
			count, ok := parseOptionalInt(taken)
			if !ok {
				return nil, fmt.Errorf("invalid BRDA line: %s", line)
			}
			if count > 0 {
				current.derivedBranchesCovered++
			}
		case line == "end_of_record":
			flush()
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flush()
	if len(filesByPath) == 0 {
		return nil, errors.New("invalid lcov report")
	}

	files := make([]FileCoverage, 0, len(filesByPath))
	report := &Report{Format: "lcov"}
	for _, file := range filesByPath {
		file.LineRate = rate(file.LinesCovered, file.LinesValid)
		file.BranchRate = rate(file.BranchesCovered, file.BranchesValid)
		report.LinesValid += file.LinesValid
		report.LinesCovered += file.LinesCovered
		report.BranchesValid += file.BranchesValid
		report.BranchesCovered += file.BranchesCovered
		files = append(files, *file)
	}
	report.LineRate = rate(report.LinesCovered, report.LinesValid)
	report.BranchRate = rate(report.BranchesCovered, report.BranchesValid)
	sortFiles(files)
	report.Files = files
	return report, nil
}
