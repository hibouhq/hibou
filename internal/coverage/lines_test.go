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
