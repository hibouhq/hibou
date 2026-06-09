package coverage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func parseGoCover(content []byte) (*Report, error) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	if err := validateGoCoverHeader(scanner); err != nil {
		return nil, err
	}

	filesByPath := make(map[string]*FileCoverage)
	for scanner.Scan() {
		entry, err := parseGoCoverEntry(scanner.Text())
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		applyGoCoverEntry(filesByPath, *entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	files := make([]FileCoverage, 0, len(filesByPath))
	report := &Report{Format: "gocover"}
	for _, file := range filesByPath {
		file.LineRate = rate(file.LinesCovered, file.LinesValid)
		report.LinesValid += file.LinesValid
		report.LinesCovered += file.LinesCovered
		files = append(files, *file)
	}
	report.LineRate = rate(report.LinesCovered, report.LinesValid)
	sortFiles(files)
	report.Files = files
	return report, nil
}

type goCoverEntry struct {
	path       string
	statements int
	count      int
}

func validateGoCoverHeader(scanner *bufio.Scanner) error {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return errors.New("empty go cover profile")
	}
	if !strings.HasPrefix(strings.TrimSpace(scanner.Text()), "mode:") {
		return errors.New("invalid go cover profile")
	}
	return nil
}

func parseGoCoverEntry(rawLine string) (*goCoverEntry, error) {
	line := strings.TrimSpace(rawLine)
	if line == "" {
		return nil, nil
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return nil, fmt.Errorf("invalid go cover line: %s", line)
	}
	path, ok := splitGoCoverPath(fields[0])
	if !ok {
		return nil, fmt.Errorf("invalid go cover file segment: %s", fields[0])
	}
	statements, statementsOK := parseOptionalInt(fields[1])
	count, countOK := parseOptionalInt(fields[2])
	if !statementsOK || !countOK {
		return nil, fmt.Errorf("invalid go cover counters: %s", line)
	}
	return &goCoverEntry{path: path, statements: statements, count: count}, nil
}

func applyGoCoverEntry(filesByPath map[string]*FileCoverage, entry goCoverEntry) {
	file := filesByPath[entry.path]
	if file == nil {
		file = &FileCoverage{Path: entry.path}
		filesByPath[entry.path] = file
	}
	file.LinesValid += entry.statements
	if entry.count > 0 {
		file.LinesCovered += entry.statements
	}
}

func splitGoCoverPath(segment string) (string, bool) {
	separator := strings.LastIndex(segment, ":")
	if separator <= 0 {
		return "", false
	}
	return strings.TrimSpace(segment[:separator]), true
}
