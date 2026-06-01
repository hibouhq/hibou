package coverage

import (
	"math"
	"testing"
)

func TestParseCobertura(t *testing.T) {
	content := []byte(`
<coverage line-rate="0.75" branch-rate="0.5" lines-valid="4" lines-covered="3" branches-valid="2" branches-covered="1">
  <packages>
    <package name="pkg">
      <classes>
        <class name="Foo" filename="pkg/foo.go">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="0" branch="true" condition-coverage="50% (1/2)" />
          </lines>
        </class>
        <class name="FooPart2" filename="pkg/foo.go">
          <lines>
            <line number="3" hits="1" />
          </lines>
        </class>
        <class name="Bar" filename="pkg/bar.go">
          <lines>
            <line number="1" hits="1" />
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>`)

	report, err := Parse(content, "cobertura")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if report.Format != "cobertura" {
		t.Fatalf("expected format cobertura, got %q", report.Format)
	}
	if report.LinesValid != 4 || report.LinesCovered != 3 {
		t.Fatalf("unexpected line totals: %+v", report)
	}
	if report.BranchesValid != 2 || report.BranchesCovered != 1 {
		t.Fatalf("unexpected branch totals: %+v", report)
	}
	if len(report.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(report.Files))
	}
	foo := report.Files[1]
	if foo.Path != "pkg/foo.go" {
		t.Fatalf("expected aggregated file pkg/foo.go, got %q", foo.Path)
	}
	if foo.LinesValid != 3 || foo.LinesCovered != 2 {
		t.Fatalf("unexpected foo line totals: %+v", foo)
	}
	if math.Abs(foo.BranchRate-0.5) > 0.0001 {
		t.Fatalf("unexpected foo branch rate: %f", foo.BranchRate)
	}
}

func TestParseLCOV(t *testing.T) {
	content := []byte(`TN:
SF:/repo/foo.go
LF:10
LH:7
BRF:4
BRH:3
end_of_record
SF:/repo/bar.go
LF:5
LH:5
end_of_record`)

	report, err := Parse(content, "lcov")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if report.LinesValid != 15 || report.LinesCovered != 12 {
		t.Fatalf("unexpected report totals: %+v", report)
	}
	if report.BranchesValid != 4 || report.BranchesCovered != 3 {
		t.Fatalf("unexpected branch totals: %+v", report)
	}
	if len(report.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(report.Files))
	}
	if report.Files[0].Path != "/repo/bar.go" || report.Files[1].Path != "/repo/foo.go" {
		t.Fatalf("files not sorted: %+v", report.Files)
	}
}

func TestParseGoCover(t *testing.T) {
	content := []byte(`mode: set
github.com/example/project/foo.go:1.1,10.1 5 1
github.com/example/project/foo.go:12.1,20.1 3 0
github.com/example/project/bar.go:1.1,3.1 2 1`)

	report, err := Parse(content, "gocover")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if report.LinesValid != 10 || report.LinesCovered != 7 {
		t.Fatalf("unexpected totals: %+v", report)
	}
	if len(report.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(report.Files))
	}
	if report.Files[1].Path != "github.com/example/project/foo.go" {
		t.Fatalf("unexpected foo path: %q", report.Files[1].Path)
	}
	if math.Abs(report.Files[1].LineRate-0.625) > 0.0001 {
		t.Fatalf("unexpected foo rate: %f", report.Files[1].LineRate)
	}
}

func TestParseJaCoCo(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<report name="demo">
  <package name="pkg">
    <sourcefile name="foo.go">
      <counter type="LINE" missed="1" covered="3"/>
      <counter type="BRANCH" missed="2" covered="2"/>
    </sourcefile>
    <sourcefile name="bar.go">
      <counter type="LINE" missed="0" covered="2"/>
    </sourcefile>
  </package>
  <counter type="LINE" missed="1" covered="5"/>
  <counter type="BRANCH" missed="2" covered="2"/>
</report>`)

	report, err := Parse(content, "jacoco")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if report.Format != "jacoco" {
		t.Fatalf("expected format jacoco, got %q", report.Format)
	}
	if report.LinesValid != 6 || report.LinesCovered != 5 {
		t.Fatalf("unexpected line totals: %+v", report)
	}
	if report.BranchesValid != 4 || report.BranchesCovered != 2 {
		t.Fatalf("unexpected branch totals: %+v", report)
	}
	if len(report.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(report.Files))
	}
	if report.Files[0].Path != "pkg/bar.go" || report.Files[1].Path != "pkg/foo.go" {
		t.Fatalf("unexpected file paths: %+v", report.Files)
	}
	if report.Files[1].LinesValid != 4 || report.Files[1].LinesCovered != 3 {
		t.Fatalf("unexpected foo totals: %+v", report.Files[1])
	}
}

func TestParseLCOVDerivedFromEntries(t *testing.T) {
	content := []byte(`SF:/repo/foo.go
DA:1,1
DA:2,0
BRDA:2,0,0,1
BRDA:2,0,1,-
end_of_record`)

	report, err := Parse(content, "lcov")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if report.LinesValid != 2 || report.LinesCovered != 1 {
		t.Fatalf("unexpected line totals: %+v", report)
	}
	if report.BranchesValid != 2 || report.BranchesCovered != 1 {
		t.Fatalf("unexpected branch totals: %+v", report)
	}
	if len(report.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(report.Files))
	}
}

func TestParseEmptyInputReturnsError(t *testing.T) {
	if _, err := Parse([]byte("  \n\t"), "lcov"); err == nil {
		t.Fatal("expected empty input error")
	}
}

func TestParseMalformedInputReturnsError(t *testing.T) {
	t.Run("cobertura xml", func(t *testing.T) {
		if _, err := Parse([]byte("<coverage"), "cobertura"); err == nil {
			t.Fatal("expected malformed XML error")
		}
	})

	t.Run("lcov entries", func(t *testing.T) {
		content := []byte("SF:/repo/foo.go\nDA:1,nope\nend_of_record")
		if _, err := Parse(content, "lcov"); err == nil {
			t.Fatal("expected malformed LCOV error")
		}
	})
}
