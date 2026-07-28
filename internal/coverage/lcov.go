package coverage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

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
	// branchesByLine accumulates BRDA records so per-line branch counters can
	// be joined onto the DA lines at flush — that's what marks a line partial.
	branchesByLine map[int]*lineBranches
}

type lineBranches struct {
	covered int
	valid   int
}

func parseLCOV(content []byte) (*Report, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	filesByPath := make(map[string]*FileCoverage)
	current := &lcovRecord{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		next, flush, err := processLCOVLine(line, current)
		if err != nil {
			return nil, err
		}
		if flush {
			flushLCOVRecord(filesByPath, current)
		}
		current = next
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flushLCOVRecord(filesByPath, current)
	if len(filesByPath) == 0 {
		return nil, errors.New("invalid lcov report")
	}

	files := make([]FileCoverage, 0, len(filesByPath))
	report := &Report{Format: "lcov"}
	for _, file := range filesByPath {
		file.LineRate = rate(file.LinesCovered, file.LinesValid)
		file.BranchRate = rate(file.BranchesCovered, file.BranchesValid)
		file.Lines = finalizeLines(file.Lines)
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

func processLCOVLine(line string, current *lcovRecord) (*lcovRecord, bool, error) {
	switch {
	case strings.HasPrefix(line, "SF:"):
		next := &lcovRecord{}
		next.file.Path = strings.TrimSpace(strings.TrimPrefix(line, "SF:"))
		return next, true, nil
	case strings.HasPrefix(line, "LF:"):
		value, ok := parseOptionalInt(strings.TrimPrefix(line, "LF:"))
		if !ok {
			return nil, false, fmt.Errorf("invalid LF line: %s", line)
		}
		current.file.LinesValid = value
		current.hasLinesValid = true
	case strings.HasPrefix(line, "LH:"):
		value, ok := parseOptionalInt(strings.TrimPrefix(line, "LH:"))
		if !ok {
			return nil, false, fmt.Errorf("invalid LH line: %s", line)
		}
		current.file.LinesCovered = value
		current.hasLinesCovered = true
	case strings.HasPrefix(line, "BRF:"):
		value, ok := parseOptionalInt(strings.TrimPrefix(line, "BRF:"))
		if !ok {
			return nil, false, fmt.Errorf("invalid BRF line: %s", line)
		}
		current.file.BranchesValid = value
		current.hasBranchesValid = true
	case strings.HasPrefix(line, "BRH:"):
		value, ok := parseOptionalInt(strings.TrimPrefix(line, "BRH:"))
		if !ok {
			return nil, false, fmt.Errorf("invalid BRH line: %s", line)
		}
		current.file.BranchesCovered = value
		current.hasBranchesCovered = true
	case strings.HasPrefix(line, "DA:"):
		if err := processLCOVDALine(line, current); err != nil {
			return nil, false, err
		}
	case strings.HasPrefix(line, "BRDA:"):
		if err := processLCOVBRDALine(line, current); err != nil {
			return nil, false, err
		}
	case line == "end_of_record":
		return &lcovRecord{}, true, nil
	}
	return current, false, nil
}

func processLCOVDALine(line string, current *lcovRecord) error {
	parts := strings.Split(strings.TrimPrefix(line, "DA:"), ",")
	if len(parts) != 2 {
		return fmt.Errorf("invalid DA line: %s", line)
	}
	number, numberOK := parseOptionalInt(parts[0])
	count, ok := parseOptionalInt(parts[1])
	if !ok {
		return fmt.Errorf("invalid DA line: %s", line)
	}
	current.derivedLinesValid++
	if count > 0 {
		current.derivedLinesCovered++
	}
	if numberOK && number > 0 {
		current.file.Lines = append(current.file.Lines, LineCoverage{Number: number, Hits: count})
	}
	return nil
}

func processLCOVBRDALine(line string, current *lcovRecord) error {
	parts := strings.Split(strings.TrimPrefix(line, "BRDA:"), ",")
	if len(parts) != 4 {
		return fmt.Errorf("invalid BRDA line: %s", line)
	}
	current.derivedBranchesValid++

	perLine := (*lineBranches)(nil)
	if number, ok := parseOptionalInt(parts[0]); ok && number > 0 {
		if current.branchesByLine == nil {
			current.branchesByLine = make(map[int]*lineBranches)
		}
		perLine = current.branchesByLine[number]
		if perLine == nil {
			perLine = &lineBranches{}
			current.branchesByLine[number] = perLine
		}
		perLine.valid++
	}

	taken := strings.TrimSpace(parts[3])
	if taken == "-" {
		// Branch never evaluated: valid but not covered.
		return nil
	}
	count, ok := parseOptionalInt(taken)
	if !ok {
		return fmt.Errorf("invalid BRDA line: %s", line)
	}
	if count > 0 {
		current.derivedBranchesCovered++
		if perLine != nil {
			perLine.covered++
		}
	}
	return nil
}

func flushLCOVRecord(filesByPath map[string]*FileCoverage, current *lcovRecord) {
	path := strings.TrimSpace(current.file.Path)
	if path == "" {
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
	for index := range current.file.Lines {
		if branches := current.branchesByLine[current.file.Lines[index].Number]; branches != nil {
			current.file.Lines[index].BranchesCovered = branches.covered
			current.file.Lines[index].BranchesValid = branches.valid
		}
	}
	target.Lines = append(target.Lines, current.file.Lines...)
}
