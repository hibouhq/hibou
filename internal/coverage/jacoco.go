package coverage

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

type jaCoCoDocument struct {
	XMLName  xml.Name        `xml:"report"`
	Counters []jaCoCoCounter `xml:"counter"`
	Packages []jaCoCoPackage `xml:"package"`
}

type jaCoCoPackage struct {
	Name        string             `xml:"name,attr"`
	SourceFiles []jaCoCoSourceFile `xml:"sourcefile"`
}

type jaCoCoSourceFile struct {
	Name     string          `xml:"name,attr"`
	Lines    []jaCoCoLine    `xml:"line"`
	Counters []jaCoCoCounter `xml:"counter"`
}

type jaCoCoLine struct {
	Nr int `xml:"nr,attr"` // source line number
	Mi int `xml:"mi,attr"` // missed instructions
	Ci int `xml:"ci,attr"` // covered instructions
}

type jaCoCoCounter struct {
	Type    string `xml:"type,attr"`
	Missed  int    `xml:"missed,attr"`
	Covered int    `xml:"covered,attr"`
}

func parseJaCoCo(content []byte) (*Report, error) {
	var doc jaCoCoDocument
	if err := xml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse jacoco: %w", err)
	}
	if doc.XMLName.Local != "report" {
		return nil, errors.New("invalid jacoco report")
	}

	report := &Report{Format: "jacoco"}
	applyJaCoCoCounters(report, doc.Counters)
	hasReportSummary := report.LinesValid > 0 || report.BranchesValid > 0

	files := buildJaCoCoFiles(doc)
	if !hasReportSummary {
		accumulateJaCoCoSummary(report, files)
	}

	if report.LinesValid == 0 && report.BranchesValid == 0 && len(files) == 0 {
		return nil, errors.New("jacoco report has no counters")
	}

	if report.LinesValid > 0 {
		report.LineRate = rate(report.LinesCovered, report.LinesValid)
	}
	if report.BranchesValid > 0 {
		report.BranchRate = rate(report.BranchesCovered, report.BranchesValid)
	}

	sortFiles(files)
	report.Files = files
	return report, nil
}

func buildJaCoCoFiles(doc jaCoCoDocument) []FileCoverage {
	files := make([]FileCoverage, 0)
	for _, pkg := range doc.Packages {
		for _, sourceFile := range pkg.SourceFiles {
			file, ok := newJaCoCoFileCoverage(pkg.Name, sourceFile)
			if ok {
				files = append(files, file)
			}
		}
	}
	return files
}

func newJaCoCoFileCoverage(pkgName string, sourceFile jaCoCoSourceFile) (FileCoverage, bool) {
	path := joinJaCoCoPath(pkgName, sourceFile.Name)
	if path == "" {
		return FileCoverage{}, false
	}
	file := FileCoverage{Path: path}
	applyJaCoCoCountersToFile(&file, sourceFile.Counters)
	file.Lines = jaCoCoLineCoverage(sourceFile.Lines)
	file.LineRate = rate(file.LinesCovered, file.LinesValid)
	file.BranchRate = rate(file.BranchesCovered, file.BranchesValid)
	return file, true
}

// jaCoCoLineCoverage converts JaCoCo per-line instruction counters into
// per-line hit records. JaCoCo reports covered (ci) and missed (mi)
// instructions rather than raw hit counts, so a line is treated as covered
// (Hits = 1) when it has any covered instructions, uncovered (Hits = 0)
// otherwise.
func jaCoCoLineCoverage(lines []jaCoCoLine) []LineCoverage {
	if len(lines) == 0 {
		return nil
	}
	result := make([]LineCoverage, 0, len(lines))
	for _, line := range lines {
		if line.Nr <= 0 {
			continue
		}
		hits := 0
		if line.Ci > 0 {
			hits = 1
		}
		result = append(result, LineCoverage{Number: line.Nr, Hits: hits})
	}
	return finalizeLines(result)
}

func accumulateJaCoCoSummary(report *Report, files []FileCoverage) {
	for _, file := range files {
		report.LinesValid += file.LinesValid
		report.LinesCovered += file.LinesCovered
		report.BranchesValid += file.BranchesValid
		report.BranchesCovered += file.BranchesCovered
	}
}

func applyJaCoCoCounters(report *Report, counters []jaCoCoCounter) {
	for _, counter := range counters {
		total := counter.Missed + counter.Covered
		switch strings.ToUpper(strings.TrimSpace(counter.Type)) {
		case "LINE":
			report.LinesValid = total
			report.LinesCovered = counter.Covered
		case "BRANCH":
			report.BranchesValid = total
			report.BranchesCovered = counter.Covered
		}
	}
}

func applyJaCoCoCountersToFile(file *FileCoverage, counters []jaCoCoCounter) {
	for _, counter := range counters {
		total := counter.Missed + counter.Covered
		switch strings.ToUpper(strings.TrimSpace(counter.Type)) {
		case "LINE":
			file.LinesValid = total
			file.LinesCovered = counter.Covered
		case "BRANCH":
			file.BranchesValid = total
			file.BranchesCovered = counter.Covered
		}
	}
}

func joinJaCoCoPath(pkgName, fileName string) string {
	pkgName = strings.Trim(strings.TrimSpace(pkgName), "/")
	fileName = strings.Trim(strings.TrimSpace(fileName), "/")
	if pkgName == "" {
		return fileName
	}
	if fileName == "" {
		return pkgName
	}
	return pkgName + "/" + fileName
}
