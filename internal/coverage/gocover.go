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
		file.Lines = finalizeLines(file.Lines)
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
	startLine  int
	endLine    int
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
	path, startLine, endLine, ok := splitGoCoverSegment(fields[0])
	if !ok {
		return nil, fmt.Errorf("invalid go cover file segment: %s", fields[0])
	}
	statements, statementsOK := parseOptionalInt(fields[1])
	count, countOK := parseOptionalInt(fields[2])
	if !statementsOK || !countOK {
		return nil, fmt.Errorf("invalid go cover counters: %s", line)
	}
	return &goCoverEntry{path: path, startLine: startLine, endLine: endLine, statements: statements, count: count}, nil
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
	// A go cover block spans [startLine, endLine]; attribute the block's
	// execution count to every source line it covers so line-level patch
	// coverage can report per-line hits.
	if entry.startLine > 0 && entry.endLine >= entry.startLine {
		for number := entry.startLine; number <= entry.endLine; number++ {
			file.Lines = append(file.Lines, LineCoverage{Number: number, Hits: entry.count})
		}
	}
}

// splitGoCoverSegment parses a go cover profile block segment of the form
// "path:startLine.startCol,endLine.endCol" into its path and line range.
func splitGoCoverSegment(segment string) (path string, startLine, endLine int, ok bool) {
	separator := strings.LastIndex(segment, ":")
	if separator <= 0 {
		return "", 0, 0, false
	}
	path = strings.TrimSpace(segment[:separator])
	block := segment[separator+1:]
	start, end, hasRange := parseGoCoverBlockRange(block)
	// Path alone is still valid; the range is best-effort for per-line data.
	return path, start, end, path != "" && (!hasRange || end >= start)
}

// parseGoCoverBlockRange parses "startLine.startCol,endLine.endCol".
func parseGoCoverBlockRange(block string) (startLine, endLine int, ok bool) {
	comma := strings.Index(block, ",")
	if comma <= 0 {
		return 0, 0, false
	}
	start, startOK := parseGoCoverLineOffset(block[:comma])
	end, endOK := parseGoCoverLineOffset(block[comma+1:])
	if !startOK || !endOK {
		return 0, 0, false
	}
	return start, end, true
}

func parseGoCoverLineOffset(value string) (int, bool) {
	if dot := strings.Index(value, "."); dot >= 0 {
		value = value[:dot]
	}
	return parseOptionalInt(value)
}
