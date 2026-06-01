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
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("empty go cover profile")
	}
	if !strings.HasPrefix(strings.TrimSpace(scanner.Text()), "mode:") {
		return nil, errors.New("invalid go cover profile")
	}

	filesByPath := make(map[string]*FileCoverage)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
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

		file := filesByPath[path]
		if file == nil {
			file = &FileCoverage{Path: path}
			filesByPath[path] = file
		}
		// NOTE: Go cover profiles count statements, not individual lines.
		// We report statements as "lines" because that's the closest semantic
		// mapping and is consistent with how tools like codecov/coveralls treat
		// Go coverage data.
		file.LinesValid += statements
		if count > 0 {
			file.LinesCovered += statements
		}
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

func splitGoCoverPath(segment string) (string, bool) {
	separator := strings.LastIndex(segment, ":")
	if separator <= 0 {
		return "", false
	}
	return strings.TrimSpace(segment[:separator]), true
}
