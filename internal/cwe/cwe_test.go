package cwe

import (
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	cases := map[string]int{
		"CWE-79":              79,
		"cwe-079":             79,
		"79":                  79,
		"CWE 89":              89,
		"\tcwe-89\n":          89,
		"external/cwe/cwe-78": 78,
		"CWE_22":              22,
	}
	for input, want := range cases {
		got, ok := Parse(input)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %d, %v; want %d", input, got, ok, want)
		}
	}
	for _, input := range []string{"", "NVD-CWE-Other", "NVD-CWE-noinfo", "CWE-0", "abc", "CWE-79x", "-5", "CWE-99999999999"} {
		if got, ok := Parse(input); ok {
			t.Errorf("Parse(%q) = %d, want rejection", input, got)
		}
	}
}

func TestParseTag(t *testing.T) {
	cases := map[string]int{
		"external/cwe/cwe-078": 78,
		"CWE-79: Improper Neutralization of Input During Web Page Generation": 79,
		"cwe-327": 327,
	}
	for tag, want := range cases {
		if got, ok := ParseTag(tag); !ok || got != want {
			t.Errorf("ParseTag(%q) = %d, %v; want %d", tag, got, ok, want)
		}
	}
	// A CWE mentioned mid-tag is not a classification, and "security"/"MEDIUM"
	// are not CWEs.
	for _, tag := range []string{"security", "MEDIUM", "see CWE-79", "OWASP-A03:2021 - Injection"} {
		if got, ok := ParseTag(tag); ok {
			t.Errorf("ParseTag(%q) = %d, want rejection", tag, got)
		}
	}
}

func TestParseAllDedupesAndDropsNoMapping(t *testing.T) {
	got := ParseAll([]string{"CWE-79", "NVD-CWE-noinfo", "cwe-079", "CWE-89"})
	if !slices.Equal(got, []int{79, 89}) {
		t.Fatalf("ParseAll = %v", got)
	}
}

func TestDefaultCatalog(t *testing.T) {
	catalog := Default()
	sql, ok := catalog.Lookup(89)
	if !ok || sql.Abstraction != "base" || sql.Name == "" {
		t.Fatalf("CWE-89 = %+v, %v", sql, ok)
	}
	top25, ok := catalog.Set("TOP25")
	if !ok || len(top25.Members) != 25 || !top25.Ranked {
		t.Fatalf("top25 = %+v, %v", top25, ok)
	}
	if rank, ok := top25.Rank(top25.Members[0]); !ok || rank != 1 {
		t.Fatalf("rank of first member = %d, %v", rank, ok)
	}
	injection, ok := catalog.Set("owasp-a03")
	if !ok || !slices.Contains(injection.Members, 89) {
		t.Fatalf("owasp-a03 should contain CWE-89: %+v", injection)
	}
	if !slices.Contains(catalog.SetsOf(89), "owasp-a03") {
		t.Fatalf("SetsOf(89) = %v", catalog.SetsOf(89))
	}
}

func TestDescendantsWalkView1000(t *testing.T) {
	catalog := Default()
	// CWE-74 (Injection) is an ancestor of CWE-89 (SQL Injection) and CWE-79
	// (XSS) in Research View 1000.
	descendants := catalog.Descendants(74)
	for _, want := range []int{74, 89, 79, 78} {
		if !slices.Contains(descendants, want) {
			t.Errorf("Descendants(74) lacks %d", want)
		}
	}
	if slices.Contains(catalog.Descendants(89), 74) {
		t.Error("descendants must not include ancestors")
	}
}

func TestSearch(t *testing.T) {
	catalog := Default()
	if got := catalog.Search("CWE-89", 5); len(got) == 0 || got[0].ID != 89 {
		t.Fatalf("Search(CWE-89) = %+v", got)
	}
	found := false
	for _, entry := range catalog.Search("sql injection", 20) {
		if entry.ID == 89 {
			found = true
		}
	}
	if !found {
		t.Fatal("title search for 'sql injection' should find CWE-89")
	}
	if got := catalog.Search("", 5); got != nil {
		t.Fatalf("empty query = %+v", got)
	}
}

func TestParseSelector(t *testing.T) {
	exact, err := ParseSelector(KindExact, []string{"CWE-79", "89"})
	if err != nil || !slices.Equal(exact.IDs, []int{79, 89}) {
		t.Fatalf("exact = %+v, %v", exact, err)
	}
	if !exact.Matches([]int{1, 89}) || exact.Matches([]int{22}) || exact.Matches(nil) {
		t.Fatal("exact selector matching is wrong")
	}

	tree, err := ParseSelector(KindTree, []string{"74"})
	if err != nil || !tree.Matches([]int{89}) {
		t.Fatalf("cwe-tree:74 should match SQL injection: %+v, %v", tree, err)
	}
	if id, ok := tree.Match([]int{22, 89}); !ok || id != 89 {
		t.Fatalf("Match = %d, %v", id, ok)
	}

	set, err := ParseSelector(KindSet, []string{"top25"})
	if err != nil || len(set.IDs) != 25 {
		t.Fatalf("cwe-set:top25 = %+v, %v", set, err)
	}

	coverage, err := ParseSelector(KindExact, []string{"none"})
	if err != nil || !coverage.Matches(nil) || coverage.Matches([]int{79}) {
		t.Fatalf("cwe:none = %+v, %v", coverage, err)
	}
	anyCWE, err := ParseSelector(KindExact, []string{"any"})
	if err != nil || anyCWE.Matches(nil) || !anyCWE.Matches([]int{79}) {
		t.Fatalf("cwe:any = %+v, %v", anyCWE, err)
	}

	// An id the catalog lacks is still a valid filter value.
	if _, err := ParseSelector(KindExact, []string{"99999"}); err != nil {
		t.Fatalf("unknown but well-formed id rejected: %v", err)
	}
	for kind, values := range map[string][]string{
		KindExact: {"abc"},
		KindTree:  {"none"},
		KindSet:   {"top-26"},
		"cwe-x":   {"1"},
	} {
		if _, err := ParseSelector(kind, values); err == nil {
			t.Errorf("ParseSelector(%s, %v) accepted", kind, values)
		}
	}
}

// View 1400 puts every weakness in exactly one category; the AI/LLM
// weaknesses land under Injection like their classic counterparts.
func TestCategories(t *testing.T) {
	catalog := Default()
	for id, want := range map[int]string{89: "injection", 79: "injection", 1427: "injection", 327: "encryption", 22: "file-handling"} {
		if ref := catalog.CategoryRef(id); ref == nil || ref.Slug != want {
			t.Errorf("CategoryRef(%d) = %+v, want %s", id, ref, want)
		}
	}
	if len(catalog.CategorySlugs()) < 20 {
		t.Fatalf("categories = %v", catalog.CategorySlugs())
	}
	selector, err := ParseSelector(KindCategory, []string{"Injection"})
	if err != nil || !selector.Matches([]int{89}) || selector.Matches([]int{327}) {
		t.Fatalf("cwe-category:injection = %+v, %v", selector, err)
	}
	// Categories are not sets: cwe-set does not resolve them, and set
	// memberships on a CWE list rankings/OWASP only.
	if _, err := ParseSelector(KindSet, []string{"injection"}); err == nil {
		t.Fatal("cwe-set:injection resolved a category")
	}
	for _, slug := range catalog.SetsOf(89) {
		if slug == "injection" {
			t.Fatal("SetsOf must not list categories")
		}
	}
}

func TestAncestorsAndRoots(t *testing.T) {
	catalog := Default()
	ancestors := catalog.Ancestors(89)
	if len(ancestors) == 0 || ancestors[0] != 943 || !slices.Contains(ancestors, 74) {
		t.Fatalf("Ancestors(89) = %v, want 943 first and 74 among them", ancestors)
	}
	pillars := catalog.ByAbstraction("pillar")
	if len(pillars) < 5 || len(pillars) > 20 {
		t.Fatalf("pillars = %d", len(pillars))
	}
	for _, pillar := range pillars {
		if len(pillar.Parents) != 0 {
			t.Errorf("pillar CWE-%d has parents %v", pillar.ID, pillar.Parents)
		}
	}
}
