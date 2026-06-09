package coverage

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var branchCoveragePattern = regexp.MustCompile(`\((\d+)/(\d+)\)`)

type coberturaDocument struct {
	XMLName         xml.Name           `xml:"coverage"`
	LineRate        string             `xml:"line-rate,attr"`
	BranchRate      string             `xml:"branch-rate,attr"`
	LinesValid      string             `xml:"lines-valid,attr"`
	LinesCovered    string             `xml:"lines-covered,attr"`
	BranchesValid   string             `xml:"branches-valid,attr"`
	BranchesCovered string             `xml:"branches-covered,attr"`
	Packages        []coberturaPackage `xml:"packages>package"`
	Classes         []coberturaClass   `xml:"classes>class"`
}

type coberturaPackage struct {
	Classes []coberturaClass `xml:"classes>class"`
}

type coberturaClass struct {
	Filename string          `xml:"filename,attr"`
	Lines    []coberturaLine `xml:"lines>line"`
}

type coberturaLine struct {
	Hits              int    `xml:"hits,attr"`
	Branch            string `xml:"branch,attr"`
	ConditionCoverage string `xml:"condition-coverage,attr"`
}

func parseCobertura(content []byte) (*Report, error) {
	var doc coberturaDocument
	if err := xml.Unmarshal(content, &doc); err == nil {
		report := reportFromCobertura(doc)
		if report != nil {
			return report, nil
		}
	}

	report, err := parseXMLSummary(content)
	if err != nil {
		return nil, fmt.Errorf("parse cobertura: %w", err)
	}
	return report, nil
}

func reportFromCobertura(doc coberturaDocument) *Report {
	filesByPath := make(map[string]*FileCoverage)
	classes := coberturaClasses(doc)

	for _, class := range classes {
		applyCoberturaClass(filesByPath, class)
	}

	files := make([]FileCoverage, 0, len(filesByPath))
	for _, file := range filesByPath {
		file.LineRate = rate(file.LinesCovered, file.LinesValid)
		file.BranchRate = rate(file.BranchesCovered, file.BranchesValid)
		files = append(files, *file)
	}

	summary := buildCoberturaSummary(doc, files)

	if len(files) == 0 && !summary.hasCounts && !summary.hasLineRate && !summary.hasBranchRate {
		return nil
	}

	sortFiles(files)
	return &Report{
		Format:          "cobertura",
		LineRate:        summary.lineRate,
		BranchRate:      summary.branchRate,
		LinesValid:      summary.linesValid,
		LinesCovered:    summary.linesCovered,
		BranchesValid:   summary.branchesValid,
		BranchesCovered: summary.branchesCovered,
		Files:           files,
	}
}

type coberturaSummary struct {
	lineRate        float64
	branchRate      float64
	linesValid      int
	linesCovered    int
	branchesValid   int
	branchesCovered int
	hasCounts       bool
	hasLineRate     bool
	hasBranchRate   bool
}

func coberturaClasses(doc coberturaDocument) []coberturaClass {
	classes := append([]coberturaClass{}, doc.Classes...)
	for _, pkg := range doc.Packages {
		classes = append(classes, pkg.Classes...)
	}
	return classes
}

func applyCoberturaClass(filesByPath map[string]*FileCoverage, class coberturaClass) {
	path := strings.TrimSpace(class.Filename)
	if path == "" {
		return
	}
	file := filesByPath[path]
	if file == nil {
		file = &FileCoverage{Path: path}
		filesByPath[path] = file
	}
	for _, line := range class.Lines {
		applyCoberturaLine(file, line)
	}
}

func applyCoberturaLine(file *FileCoverage, line coberturaLine) {
	file.LinesValid++
	if line.Hits > 0 {
		file.LinesCovered++
	}
	covered, valid := parseBranchCoverage(line)
	file.BranchesCovered += covered
	file.BranchesValid += valid
}

func buildCoberturaSummary(doc coberturaDocument, files []FileCoverage) coberturaSummary {
	summary := coberturaSummary{}
	summary.linesValid, summary.hasCounts = parseOptionalInt(doc.LinesValid)
	summary.linesCovered, _ = parseOptionalInt(doc.LinesCovered)
	summary.branchesValid, _ = parseOptionalInt(doc.BranchesValid)
	summary.branchesCovered, _ = parseOptionalInt(doc.BranchesCovered)
	summary.lineRate, summary.hasLineRate = parseOptionalFloat(doc.LineRate)
	summary.branchRate, summary.hasBranchRate = parseOptionalFloat(doc.BranchRate)
	if !summary.hasCounts || !docHasCoberturaCounts(doc) {
		summary = aggregateCoberturaSummary(summary, files)
	}
	if !summary.hasLineRate {
		summary.lineRate = rate(summary.linesCovered, summary.linesValid)
	}
	if !summary.hasBranchRate {
		summary.branchRate = rate(summary.branchesCovered, summary.branchesValid)
	}
	return summary
}

func docHasCoberturaCounts(doc coberturaDocument) bool {
	_, okLinesValid := parseOptionalInt(doc.LinesValid)
	_, okLinesCovered := parseOptionalInt(doc.LinesCovered)
	_, okBranchesValid := parseOptionalInt(doc.BranchesValid)
	_, okBranchesCovered := parseOptionalInt(doc.BranchesCovered)
	return okLinesValid && okLinesCovered && okBranchesValid && okBranchesCovered
}

func aggregateCoberturaSummary(summary coberturaSummary, files []FileCoverage) coberturaSummary {
	summary.linesValid = 0
	summary.linesCovered = 0
	summary.branchesValid = 0
	summary.branchesCovered = 0
	for _, file := range files {
		summary.linesValid += file.LinesValid
		summary.linesCovered += file.LinesCovered
		summary.branchesValid += file.BranchesValid
		summary.branchesCovered += file.BranchesCovered
	}
	return summary
}

func parseBranchCoverage(line coberturaLine) (int, int) {
	if strings.EqualFold(strings.TrimSpace(line.Branch), "true") {
		matches := branchCoveragePattern.FindStringSubmatch(line.ConditionCoverage)
		if len(matches) == 3 {
			covered, errCovered := strconv.Atoi(matches[1])
			valid, errValid := strconv.Atoi(matches[2])
			if errCovered == nil && errValid == nil {
				return covered, valid
			}
		}
		return 0, 0
	}
	return 0, 0
}

func parseXMLSummary(content []byte) (*Report, error) {
	decoder := xml.NewDecoder(bytes.NewReader(content))

	state := xmlSummaryState{}

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		if !state.rootSeen {
			handleXMLSummaryRoot(&state, start)
		}

		switch start.Name.Local {
		case "counter":
			handleXMLSummaryCounter(&state, start)
		case "metrics":
			handleXMLSummaryMetrics(&state, start)
		}
	}

	if !state.hasSummary {
		return nil, errors.New("unsupported coverage XML structure")
	}

	return &Report{
		Format:          "cobertura",
		LineRate:        state.lineRate,
		BranchRate:      state.branchRate,
		LinesValid:      state.linesValid,
		LinesCovered:    state.linesCovered,
		BranchesValid:   state.branchesValid,
		BranchesCovered: state.branchesCovered,
	}, nil
}

type xmlSummaryState struct {
	lineRate        float64
	branchRate      float64
	linesValid      int
	linesCovered    int
	branchesValid   int
	branchesCovered int
	hasSummary      bool
	rootSeen        bool
}

func handleXMLSummaryRoot(state *xmlSummaryState, start xml.StartElement) {
	state.rootSeen = true
	if value, ok := attrFloat(start.Attr, "line-rate"); ok {
		state.lineRate = value
		state.hasSummary = true
	}
	if value, ok := attrFloat(start.Attr, "branch-rate"); ok {
		state.branchRate = value
		state.hasSummary = true
	}
	if value, ok := attrInt(start.Attr, "lines-valid"); ok {
		state.linesValid = value
		state.hasSummary = true
	}
	if value, ok := attrInt(start.Attr, "lines-covered"); ok {
		state.linesCovered = value
		state.hasSummary = true
	}
	if value, ok := attrInt(start.Attr, "branches-valid"); ok {
		state.branchesValid = value
		state.hasSummary = true
	}
	if value, ok := attrInt(start.Attr, "branches-covered"); ok {
		state.branchesCovered = value
		state.hasSummary = true
	}
}

func handleXMLSummaryCounter(state *xmlSummaryState, start xml.StartElement) {
	typ, _ := attrString(start.Attr, "type")
	missed, missedOK := attrInt(start.Attr, "missed")
	covered, coveredOK := attrInt(start.Attr, "covered")
	if !missedOK || !coveredOK {
		return
	}
	total := missed + covered
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "LINE":
		if total >= state.linesValid {
			state.linesCovered = covered
			state.linesValid = total
			state.lineRate = rate(state.linesCovered, state.linesValid)
			state.hasSummary = true
		}
	case "BRANCH":
		if total >= state.branchesValid {
			state.branchesCovered = covered
			state.branchesValid = total
			state.branchRate = rate(state.branchesCovered, state.branchesValid)
			state.hasSummary = true
		}
	}
}

func handleXMLSummaryMetrics(state *xmlSummaryState, start xml.StartElement) {
	metricLinesValid, metricLinesValidOK := attrInt(start.Attr, "statements")
	metricLinesCovered, metricLinesCoveredOK := attrInt(start.Attr, "coveredstatements")
	metricBranchesValid, metricBranchesValidOK := attrInt(start.Attr, "conditionals")
	metricBranchesCovered, metricBranchesCoveredOK := attrInt(start.Attr, "coveredconditionals")
	if metricLinesValidOK && metricLinesCoveredOK && metricLinesValid >= state.linesValid {
		state.linesValid = metricLinesValid
		state.linesCovered = metricLinesCovered
		state.lineRate = rate(state.linesCovered, state.linesValid)
		state.hasSummary = true
	}
	if metricBranchesValidOK && metricBranchesCoveredOK && metricBranchesValid >= state.branchesValid {
		state.branchesValid = metricBranchesValid
		state.branchesCovered = metricBranchesCovered
		state.branchRate = rate(state.branchesCovered, state.branchesValid)
		state.hasSummary = true
	}
}

func attrString(attrs []xml.Attr, name string) (string, bool) {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return strings.TrimSpace(attr.Value), true
		}
	}
	return "", false
}

func attrInt(attrs []xml.Attr, name string) (int, bool) {
	value, ok := attrString(attrs, name)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func attrFloat(attrs []xml.Attr, name string) (float64, bool) {
	value, ok := attrString(attrs, name)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func parseOptionalInt(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func parseOptionalFloat(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
