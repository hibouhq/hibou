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
	classes := append([]coberturaClass{}, doc.Classes...)
	for _, pkg := range doc.Packages {
		classes = append(classes, pkg.Classes...)
	}

	for _, class := range classes {
		path := strings.TrimSpace(class.Filename)
		if path == "" {
			continue
		}
		file := filesByPath[path]
		if file == nil {
			file = &FileCoverage{Path: path}
			filesByPath[path] = file
		}
		for _, line := range class.Lines {
			file.LinesValid++
			if line.Hits > 0 {
				file.LinesCovered++
			}
			covered, valid := parseBranchCoverage(line)
			file.BranchesCovered += covered
			file.BranchesValid += valid
		}
	}

	files := make([]FileCoverage, 0, len(filesByPath))
	for _, file := range filesByPath {
		file.LineRate = rate(file.LinesCovered, file.LinesValid)
		file.BranchRate = rate(file.BranchesCovered, file.BranchesValid)
		files = append(files, *file)
	}

	linesValid, okLinesValid := parseOptionalInt(doc.LinesValid)
	linesCovered, okLinesCovered := parseOptionalInt(doc.LinesCovered)
	branchesValid, okBranchesValid := parseOptionalInt(doc.BranchesValid)
	branchesCovered, okBranchesCovered := parseOptionalInt(doc.BranchesCovered)
	lineRate, okLineRate := parseOptionalFloat(doc.LineRate)
	branchRate, okBranchRate := parseOptionalFloat(doc.BranchRate)

	if !okLinesValid || !okLinesCovered || !okBranchesValid || !okBranchesCovered {
		for _, file := range files {
			linesValid += file.LinesValid
			linesCovered += file.LinesCovered
			branchesValid += file.BranchesValid
			branchesCovered += file.BranchesCovered
		}
	}
	if !okLineRate {
		lineRate = rate(linesCovered, linesValid)
	}
	if !okBranchRate {
		branchRate = rate(branchesCovered, branchesValid)
	}

	if len(files) == 0 && !okLinesValid && !okLineRate && !okBranchRate {
		return nil
	}

	sortFiles(files)
	return &Report{
		Format:          "cobertura",
		LineRate:        lineRate,
		BranchRate:      branchRate,
		LinesValid:      linesValid,
		LinesCovered:    linesCovered,
		BranchesValid:   branchesValid,
		BranchesCovered: branchesCovered,
		Files:           files,
	}
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

	var (
		lineRate        float64
		branchRate      float64
		linesValid      int
		linesCovered    int
		branchesValid   int
		branchesCovered int
		hasSummary      bool
		rootSeen        bool
	)

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

		if !rootSeen {
			rootSeen = true
			if value, ok := attrFloat(start.Attr, "line-rate"); ok {
				lineRate = value
				hasSummary = true
			}
			if value, ok := attrFloat(start.Attr, "branch-rate"); ok {
				branchRate = value
				hasSummary = true
			}
			if value, ok := attrInt(start.Attr, "lines-valid"); ok {
				linesValid = value
				hasSummary = true
			}
			if value, ok := attrInt(start.Attr, "lines-covered"); ok {
				linesCovered = value
				hasSummary = true
			}
			if value, ok := attrInt(start.Attr, "branches-valid"); ok {
				branchesValid = value
				hasSummary = true
			}
			if value, ok := attrInt(start.Attr, "branches-covered"); ok {
				branchesCovered = value
				hasSummary = true
			}
		}

		switch start.Name.Local {
		case "counter":
			typ, _ := attrString(start.Attr, "type")
			missed, missedOK := attrInt(start.Attr, "missed")
			covered, coveredOK := attrInt(start.Attr, "covered")
			if !missedOK || !coveredOK {
				continue
			}
			total := missed + covered
			switch strings.ToUpper(strings.TrimSpace(typ)) {
			case "LINE":
				if total >= linesValid {
					linesCovered = covered
					linesValid = total
					lineRate = rate(linesCovered, linesValid)
					hasSummary = true
				}
			case "BRANCH":
				if total >= branchesValid {
					branchesCovered = covered
					branchesValid = total
					branchRate = rate(branchesCovered, branchesValid)
					hasSummary = true
				}
			}
		case "metrics":
			metricLinesValid, metricLinesValidOK := attrInt(start.Attr, "statements")
			metricLinesCovered, metricLinesCoveredOK := attrInt(start.Attr, "coveredstatements")
			metricBranchesValid, metricBranchesValidOK := attrInt(start.Attr, "conditionals")
			metricBranchesCovered, metricBranchesCoveredOK := attrInt(start.Attr, "coveredconditionals")
			if metricLinesValidOK && metricLinesCoveredOK && metricLinesValid >= linesValid {
				linesValid = metricLinesValid
				linesCovered = metricLinesCovered
				lineRate = rate(linesCovered, linesValid)
				hasSummary = true
			}
			if metricBranchesValidOK && metricBranchesCoveredOK && metricBranchesValid >= branchesValid {
				branchesValid = metricBranchesValid
				branchesCovered = metricBranchesCovered
				branchRate = rate(branchesCovered, branchesValid)
				hasSummary = true
			}
		}
	}

	if !hasSummary {
		return nil, errors.New("unsupported coverage XML structure")
	}

	return &Report{
		Format:          "cobertura",
		LineRate:        lineRate,
		BranchRate:      branchRate,
		LinesValid:      linesValid,
		LinesCovered:    linesCovered,
		BranchesValid:   branchesValid,
		BranchesCovered: branchesCovered,
	}, nil
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
