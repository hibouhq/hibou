package testresults

import (
	"encoding/xml"
	"errors"
	"strings"
)

type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Time    float64          `xml:"time,attr"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	XMLName xml.Name         `xml:"testsuite"`
	Name    string           `xml:"name,attr"`
	Time    float64          `xml:"time,attr"`
	Suites  []junitTestSuite `xml:"testsuite"` // some emitters nest suites
	Cases   []junitTestCase  `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	File      string        `xml:"file,attr"`
	Failure   *junitDetail  `xml:"failure"`
	Error     *junitDetail  `xml:"error"`
	Skipped   *junitSkipped `xml:"skipped"`
}

type junitDetail struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func parseJUnit(content []byte) (*Report, error) {
	var multi junitTestSuites
	var suites []junitTestSuite
	if err := xml.Unmarshal(content, &multi); err == nil && len(multi.Suites) > 0 {
		suites = multi.Suites
	} else {
		var single junitTestSuite
		if err := xml.Unmarshal(content, &single); err != nil {
			return nil, errors.New("invalid JUnit XML report")
		}
		if single.Name == "" && len(single.Cases) == 0 && len(single.Suites) == 0 {
			return nil, errors.New("invalid JUnit XML report")
		}
		suites = []junitTestSuite{single}
	}

	report := &Report{Format: "junit", DurationSeconds: multi.Time}
	for i := range suites {
		collectJUnitSuite(report, &suites[i], "")
	}
	report.tally()

	// Fall back to summing case durations when no suite/root time was reported.
	if report.DurationSeconds == 0 {
		for _, c := range report.Cases {
			report.DurationSeconds += c.DurationSeconds
		}
	}

	return report, nil
}

func collectJUnitSuite(report *Report, suite *junitTestSuite, parent string) {
	name := suite.Name
	if parent != "" && name != "" {
		name = parent + " / " + name
	} else if name == "" {
		name = parent
	}

	for _, tc := range suite.Cases {
		report.Cases = append(report.Cases, junitCaseToCase(tc, name))
	}
	for i := range suite.Suites {
		collectJUnitSuite(report, &suite.Suites[i], name)
	}
}

func junitCaseToCase(tc junitTestCase, suite string) Case {
	c := Case{
		Suite:           suite,
		Name:            tc.Name,
		Classname:       tc.Classname,
		Status:          StatusPassed,
		DurationSeconds: tc.Time,
		FilePath:        tc.File,
	}

	switch {
	case tc.Failure != nil:
		c.Status = StatusFailed
		c.Message = junitDetailMessage(tc.Failure)
	case tc.Error != nil:
		c.Status = StatusError
		c.Message = junitDetailMessage(tc.Error)
	case tc.Skipped != nil:
		c.Status = StatusSkipped
		c.Message = strings.TrimSpace(tc.Skipped.Message)
	}

	return c
}

func junitDetailMessage(detail *junitDetail) string {
	message := strings.TrimSpace(detail.Message)
	if message == "" {
		message = strings.TrimSpace(detail.Text)
	}
	if message == "" {
		message = strings.TrimSpace(detail.Type)
	}
	return message
}
