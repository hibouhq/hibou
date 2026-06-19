package testresults

import "testing"

func TestParseJUnitCountsAndStatuses(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<testsuites time="1.5">
  <testsuite name="pkg/auth" time="1.0">
    <testcase name="TestLogin" classname="auth" time="0.2"/>
    <testcase name="TestLogout" classname="auth" time="0.3">
      <failure message="expected 200, got 500">stack trace here</failure>
    </testcase>
    <testcase name="TestLegacy" classname="auth" time="0">
      <skipped message="deprecated"/>
    </testcase>
    <testcase name="TestPanic" classname="auth" time="0.1">
      <error message="nil pointer">panic</error>
    </testcase>
  </testsuite>
</testsuites>`

	report, err := Parse([]byte(xml), "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if report.Total != 4 || report.Passed != 1 || report.Failed != 1 || report.Skipped != 1 || report.Errors != 1 {
		t.Fatalf("unexpected tally: %+v", report)
	}
	if report.DurationSeconds != 1.5 {
		t.Fatalf("expected duration 1.5, got %v", report.DurationSeconds)
	}
	if report.Cases[0].Suite != "pkg/auth" {
		t.Fatalf("expected suite name, got %q", report.Cases[0].Suite)
	}
	if report.Cases[1].Status != StatusFailed || report.Cases[1].Message != "expected 200, got 500" {
		t.Fatalf("unexpected failure case: %+v", report.Cases[1])
	}
}

func TestParseSingleTestsuiteRoot(t *testing.T) {
	const xml = `<testsuite name="solo" tests="1"><testcase name="ok" time="0.1"/></testsuite>`
	report, err := Parse([]byte(xml), "junit")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if report.Total != 1 || report.Passed != 1 {
		t.Fatalf("unexpected tally: %+v", report)
	}
}

func TestParseRejectsEmptyAndUnknown(t *testing.T) {
	if _, err := Parse(nil, "junit"); err == nil {
		t.Fatal("expected error for empty content")
	}
	if _, err := Parse([]byte("<testsuites/>"), "rspec"); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}
