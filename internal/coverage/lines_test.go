package coverage

import "testing"

// lineHits reduces a file's per-line records to a number->hits map for assertions.
func lineHits(t *testing.T, report *Report, path string) map[int]int {
	t.Helper()
	for _, file := range report.Files {
		if file.Path == path {
			out := make(map[int]int, len(file.Lines))
			for _, line := range file.Lines {
				out[line.Number] = line.Hits
			}
			return out
		}
	}
	t.Fatalf("file %q not found in report (%+v)", path, report.Files)
	return nil
}

// assertSortedUnique verifies per-line records are sorted ascending with no
// duplicate line numbers, the contract finalizeLines guarantees.
func assertSortedUnique(t *testing.T, lines []LineCoverage) {
	t.Helper()
	seen := make(map[int]struct{}, len(lines))
	prev := 0
	for _, line := range lines {
		if line.Number <= prev {
			t.Fatalf("lines not strictly ascending: %+v", lines)
		}
		if _, dup := seen[line.Number]; dup {
			t.Fatalf("duplicate line number %d: %+v", line.Number, lines)
		}
		seen[line.Number] = struct{}{}
		prev = line.Number
	}
}

func TestParseCoberturaLines(t *testing.T) {
	content := []byte(`
<coverage>
  <packages>
    <package name="pkg">
      <classes>
        <class name="Foo" filename="pkg/foo.go">
          <lines>
            <line number="1" hits="1" />
            <line number="2" hits="0" />
          </lines>
        </class>
        <class name="FooPart2" filename="pkg/foo.go">
          <lines>
            <line number="3" hits="4" />
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
	hits := lineHits(t, report, "pkg/foo.go")
	if hits[1] != 1 || hits[2] != 0 || hits[3] != 4 {
		t.Fatalf("unexpected per-line hits: %+v", hits)
	}
	for _, f := range report.Files {
		assertSortedUnique(t, f.Lines)
	}
}

func TestParseCoberturaLinesDedupeMaxHits(t *testing.T) {
	// The same line appears twice with different hit counts; the covered
	// reading must win so a line executed by any run counts as covered.
	content := []byte(`
<coverage>
  <packages>
    <package name="pkg">
      <classes>
        <class name="A" filename="pkg/foo.go">
          <lines><line number="10" hits="0" /></lines>
        </class>
        <class name="B" filename="pkg/foo.go">
          <lines><line number="10" hits="3" /></lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>`)

	report, err := Parse(content, "cobertura")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if hits := lineHits(t, report, "pkg/foo.go"); hits[10] != 3 {
		t.Fatalf("expected deduped max hits 3 for line 10, got %+v", hits)
	}
}

func TestParseLCOVLines(t *testing.T) {
	content := []byte(`SF:/repo/foo.go
DA:1,1
DA:2,0
DA:5,9
end_of_record`)

	report, err := Parse(content, "lcov")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	hits := lineHits(t, report, "/repo/foo.go")
	if hits[1] != 1 || hits[2] != 0 || hits[5] != 9 {
		t.Fatalf("unexpected per-line hits: %+v", hits)
	}
	if _, ok := hits[3]; ok {
		t.Fatalf("line 3 should not be instrumented: %+v", hits)
	}
}

func TestParseGoCoverLines(t *testing.T) {
	content := []byte(`mode: set
github.com/example/project/foo.go:1.10,3.2 2 1
github.com/example/project/foo.go:5.1,6.20 1 0`)

	report, err := Parse(content, "gocover")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	hits := lineHits(t, report, "github.com/example/project/foo.go")
	// Covered block spans lines 1..3, uncovered block spans 5..6.
	for _, n := range []int{1, 2, 3} {
		if hits[n] != 1 {
			t.Fatalf("expected line %d covered, got %+v", n, hits)
		}
	}
	for _, n := range []int{5, 6} {
		if got, ok := hits[n]; !ok || got != 0 {
			t.Fatalf("expected line %d instrumented-uncovered, got %+v", n, hits)
		}
	}
	if _, ok := hits[4]; ok {
		t.Fatalf("gap line 4 should not be instrumented: %+v", hits)
	}
}

func TestParseJaCoCoLines(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<report name="demo">
  <package name="pkg">
    <sourcefile name="Foo.java">
      <line nr="10" mi="0" ci="3" mb="0" cb="0"/>
      <line nr="11" mi="2" ci="0" mb="0" cb="0"/>
      <counter type="LINE" missed="1" covered="1"/>
    </sourcefile>
  </package>
</report>`)

	report, err := Parse(content, "jacoco")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	hits := lineHits(t, report, "pkg/Foo.java")
	if hits[10] != 1 {
		t.Fatalf("expected line 10 covered, got %+v", hits)
	}
	if got, ok := hits[11]; !ok || got != 0 {
		t.Fatalf("expected line 11 instrumented-uncovered, got %+v", hits)
	}
}

// Partial coverage: the line ran, but a condition never took both outcomes.
func TestParseJaCoCoPartialBranches(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<report name="demo">
  <package name="pkg">
    <sourcefile name="Foo.java">
      <line nr="5" mi="0" ci="4" mb="1" cb="1"/>
      <line nr="6" mi="0" ci="2" mb="0" cb="2"/>
      <line nr="7" mi="0" ci="1" mb="0" cb="0"/>
      <counter type="LINE" missed="0" covered="3"/>
      <counter type="BRANCH" missed="1" covered="3"/>
    </sourcefile>
  </package>
</report>`)

	report, err := Parse(content, "jacoco")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	lines := lineByNumber(t, report, "pkg/Foo.java")
	partial := lines[5]
	if partial.BranchesCovered != 1 || partial.BranchesValid != 2 {
		t.Fatalf("line 5 branches = %d/%d, want 1/2 (partial)", partial.BranchesCovered, partial.BranchesValid)
	}
	full := lines[6]
	if full.BranchesCovered != 2 || full.BranchesValid != 2 {
		t.Fatalf("line 6 branches = %d/%d, want 2/2", full.BranchesCovered, full.BranchesValid)
	}
	if plain := lines[7]; plain.BranchesValid != 0 {
		t.Fatalf("line 7 branches_valid = %d, want 0 (no branch on line)", plain.BranchesValid)
	}
}

func TestParseLCOVPartialBranches(t *testing.T) {
	content := []byte(`SF:src/util.js
DA:5,3
DA:6,1
BRDA:5,0,0,3
BRDA:5,0,1,0
BRDA:5,1,0,-
end_of_record`)

	report, err := Parse(content, "lcov")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	lines := lineByNumber(t, report, "src/util.js")
	partial := lines[5]
	// Three branch records on line 5, one taken: 1/3 — covered line, partial.
	if partial.Hits != 3 || partial.BranchesCovered != 1 || partial.BranchesValid != 3 {
		t.Fatalf("line 5 = hits %d branches %d/%d, want 3 and 1/3", partial.Hits, partial.BranchesCovered, partial.BranchesValid)
	}
	if plain := lines[6]; plain.BranchesValid != 0 {
		t.Fatalf("line 6 branches_valid = %d, want 0", plain.BranchesValid)
	}
}

func TestParseCoberturaPartialBranches(t *testing.T) {
	content := []byte(`<?xml version="1.0"?>
<coverage line-rate="1" branch-rate="0.5">
  <packages>
    <package name="app">
      <classes>
        <class filename="app/logic.py">
          <lines>
            <line number="8" hits="4" branch="true" condition-coverage="50% (1/2)"/>
            <line number="9" hits="2" branch="false"/>
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
	lines := lineByNumber(t, report, "app/logic.py")
	partial := lines[8]
	if partial.BranchesCovered != 1 || partial.BranchesValid != 2 {
		t.Fatalf("line 8 branches = %d/%d, want 1/2", partial.BranchesCovered, partial.BranchesValid)
	}
	if plain := lines[9]; plain.BranchesValid != 0 {
		t.Fatalf("line 9 branches_valid = %d, want 0", plain.BranchesValid)
	}
}

func lineByNumber(t *testing.T, report *Report, path string) map[int]LineCoverage {
	t.Helper()
	for _, file := range report.Files {
		if file.Path == path {
			result := make(map[int]LineCoverage, len(file.Lines))
			for _, line := range file.Lines {
				result[line.Number] = line
			}
			return result
		}
	}
	t.Fatalf("file %s not found in report (files: %+v)", path, report.Files)
	return nil
}
