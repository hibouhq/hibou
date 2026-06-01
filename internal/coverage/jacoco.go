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
	Counters []jaCoCoCounter `xml:"counter"`
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

	files := make([]FileCoverage, 0)
	for _, pkg := range doc.Packages {
		for _, sourceFile := range pkg.SourceFiles {
			path := joinJaCoCoPath(pkg.Name, sourceFile.Name)
			if path == "" {
				continue
			}

			file := FileCoverage{Path: path}
			applyJaCoCoCountersToFile(&file, sourceFile.Counters)
			file.LineRate = rate(file.LinesCovered, file.LinesValid)
			file.BranchRate = rate(file.BranchesCovered, file.BranchesValid)
			files = append(files, file)

			if !hasReportSummary {
				report.LinesValid += file.LinesValid
				report.LinesCovered += file.LinesCovered
				report.BranchesValid += file.BranchesValid
				report.BranchesCovered += file.BranchesCovered
			}
		}
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
