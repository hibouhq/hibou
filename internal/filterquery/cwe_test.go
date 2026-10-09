package filterquery

import (
	"database/sql/driver"
	"slices"
	"strings"
	"testing"
)

func compile(t *testing.T, query string) SQLResult {
	t.Helper()
	node, err := Parse(query)
	if err != nil {
		t.Fatalf("Parse(%q): %v", query, err)
	}
	result, err := ToSQL(node, 2)
	if err != nil {
		t.Fatalf("ToSQL(%q): %v", query, err)
	}
	return result
}

// arrayParam unwraps a pq.Array parameter into its ints.
func arrayParam(t *testing.T, param interface{}) []int {
	t.Helper()
	valuer, ok := param.(driver.Valuer)
	if !ok {
		t.Fatalf("param %T is not a driver.Valuer", param)
	}
	raw, err := valuer.Value()
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Trim(raw.(string), "{}")
	out := []int{}
	for _, part := range strings.Split(text, ",") {
		var value int
		for _, digit := range part {
			value = value*10 + int(digit-'0')
		}
		out = append(out, value)
	}
	return out
}

func TestCWEQualifierCompilesToHashedSubplans(t *testing.T) {
	result := compile(t, "cwe:CWE-79,89")
	for _, branch := range []string{
		"v.rule_ref_id IN (SELECT scan_rule_id FROM scan_rule_cwes WHERE cwe_id = ANY($2::int[]))",
		"v.advisory_id IN (SELECT advisory_id FROM advisory_cwes WHERE cwe_id = ANY($2::int[]))",
		"source = 'sarif_result'",
		"v.type = 'manual' AND",
	} {
		if !strings.Contains(result.Where, branch) {
			t.Fatalf("where lacks %q: %s", branch, result.Where)
		}
	}
	if strings.Contains(result.Where, "v.type = 'secret'") {
		t.Fatalf("secret branch only applies when CWE-798 is selected: %s", result.Where)
	}
	if got := arrayParam(t, result.Params[0]); !slices.Equal(got, []int{79, 89}) {
		t.Fatalf("params = %v", got)
	}
}

func TestCWE798MatchesSecretsWithoutSubquery(t *testing.T) {
	if result := compile(t, "cwe:798"); !strings.Contains(result.Where, " OR v.type = 'secret')") {
		t.Fatalf("cwe:798 must include leaked secrets: %s", result.Where)
	}
}

func TestCWETreeAndSetExpandFromCatalog(t *testing.T) {
	tree := arrayParam(t, compile(t, "cwe-tree:74").Params[0])
	if !slices.Contains(tree, 74) || !slices.Contains(tree, 89) || !slices.Contains(tree, 79) {
		t.Fatalf("cwe-tree:74 should expand to injection descendants, got %d ids", len(tree))
	}
	set := arrayParam(t, compile(t, "cwe-set:top25").Params[0])
	if len(set) != 25 {
		t.Fatalf("cwe-set:top25 = %d ids", len(set))
	}
}

func TestCWECoverageTests(t *testing.T) {
	none := compile(t, "cwe:none")
	if !strings.HasPrefix(none.Where, "NOT (EXISTS (SELECT 1 FROM scan_rule_cwes WHERE scan_rule_id = v.rule_ref_id)") || len(none.Params) != 0 {
		t.Fatalf("cwe:none = %+v", none)
	}
	mixed := compile(t, "cwe:79,none")
	if !strings.HasPrefix(mixed.Where, "((v.rule_ref_id IN") || !strings.Contains(mixed.Where, " OR NOT (EXISTS") {
		t.Fatalf("cwe:79,none = %s", mixed.Where)
	}
}

// The cross-type query ADR-037 exists for: one CWE class across SAST and
// dependency findings, combined with the rest of the grammar.
func TestCWECombinesWithOtherQualifiers(t *testing.T) {
	result := compile(t, "cwe-set:owasp-a03 (type:sast OR type:dependency) severity:high")
	if !strings.Contains(result.Where, "scan_rule_cwes") || !strings.Contains(result.Where, " OR ") || len(result.Params) != 4 {
		t.Fatalf("combined = %+v", result)
	}
}

func TestBareCWETokenIsAQualifier(t *testing.T) {
	result := compile(t, "log4j CWE-79 severity:high")
	if !strings.Contains(result.Where, "scan_rule_cwes") {
		t.Fatalf("bare CWE-79 not rewritten: %s", result.Where)
	}
	// The free text before it stays a title/identifier search.
	if !strings.Contains(result.Where, "title ILIKE") || result.Params[0] != "log4j" {
		t.Fatalf("free text lost: %+v", result)
	}
}

func TestInvalidCWEValuesAreErrors(t *testing.T) {
	for _, query := range []string{"cwe:abc", "cwe-tree:none", "cwe-set:top-26", "cwe:"} {
		node, err := Parse(query)
		if err != nil {
			continue
		}
		if _, err := ToSQL(node, 2); err == nil {
			t.Errorf("%q compiled without error", query)
		}
	}
}

// GitHub-style exclusion: -key:value keeps what the qualifier would not
// match, NULL columns included.
func TestNegatedQualifier(t *testing.T) {
	result := compile(t, "cwe:400 -type:dependency,container,malware")
	if !strings.Contains(result.Where, "NOT COALESCE((type::text = ANY($3::text[])), FALSE)") {
		t.Fatalf("where = %s", result.Where)
	}
	if acceptance := compile(t, "-acceptance:risk"); acceptance.Where != "NOT COALESCE((fa.reason_kind = 'risk_accepted'), FALSE)" {
		t.Fatalf("acceptance = %s", acceptance.Where)
	}
	// A leading dash on free text is still text.
	if text := compile(t, "-foo"); !strings.Contains(text.Where, "title ILIKE") {
		t.Fatalf("-foo = %s", text.Where)
	}
	for _, query := range []string{"-:x", "-type:"} {
		if _, err := Parse(query); err == nil {
			t.Errorf("%q parsed", query)
		}
	}
}
