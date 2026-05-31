package filterquery

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseEmptyInput(t *testing.T) {
	node, err := Parse("")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if node != nil {
		t.Fatalf("expected nil node, got %T", node)
	}
}

func TestParseUnmatchedParens(t *testing.T) {
	_, err := Parse("(type:sast OR type:secret")
	if err == nil || !strings.Contains(err.Error(), "missing closing parenthesis") {
		t.Fatalf("expected missing closing parenthesis error, got %v", err)
	}
}

func TestParseRejectsExcessiveNesting(t *testing.T) {
	input := strings.Repeat("(", maxDepth+1) + "type:sast" + strings.Repeat(")", maxDepth+1)
	_, err := Parse(input)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("maximum depth of %d", maxDepth)) {
		t.Fatalf("expected maximum depth error, got %v", err)
	}
}

func TestToSQLSimpleQualifier(t *testing.T) {
	node, err := Parse("type:sast")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "type::text = $1" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 || result.Params[0] != "sast" {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLMultiValue(t *testing.T) {
	node, err := Parse("type:sast,secret")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "type::text = ANY($1::text[])" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 {
		t.Fatalf("unexpected params length: %d", len(result.Params))
	}
	assertArrayValue(t, result.Params[0], `{"sast","secret"}`)
}

func TestToSQLAnd(t *testing.T) {
	node, err := Parse("type:sast AND severity:high")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "(type::text = $1 AND severity::text = $2)" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
}

func TestToSQLOr(t *testing.T) {
	node, err := Parse("type:sast OR type:secret")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "(type::text = $1 OR type::text = $2)" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
}

func TestToSQLParentheses(t *testing.T) {
	node, err := Parse("(type:sast OR type:secret) AND severity:high")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	expected := "(((type::text = $1 OR type::text = $2)) AND severity::text = $3)"
	if result.Where != expected {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
}

func TestToSQLStatusCast(t *testing.T) {
	node, err := Parse("status:detected")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "status = $1::vulnerability_status" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
}

func TestToSQLFileILike(t *testing.T) {
	node, err := Parse("file:main")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "COALESCE(file_path, '') ILIKE '%' || $1 || '%' ESCAPE '\\\\'" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
}

func TestToolAlias(t *testing.T) {
	node, err := Parse("tool:semgrep")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "scanner_name = $1" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 || result.Params[0] != "semgrep" {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLScannerKey(t *testing.T) {
	node, err := Parse("scanner:gosec")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "scanner_name = $1" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 || result.Params[0] != "gosec" {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLFreeText(t *testing.T) {
	node, err := Parse("zlib")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	expected := "(title ILIKE '%' || $1 || '%' ESCAPE '\\\\' OR primary_identifier->>'value' ILIKE '%' || $1 || '%' ESCAPE '\\\\')"
	if result.Where != expected {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 || result.Params[0] != "zlib" {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLFreeTextWithQualifier(t *testing.T) {
	node, err := Parse("CVE-2023 type:dependency")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	expected := "((title ILIKE '%' || $1 || '%' ESCAPE '\\\\' OR primary_identifier->>'value' ILIKE '%' || $1 || '%' ESCAPE '\\\\') AND type::text = $2)"
	if result.Where != expected {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if !reflect.DeepEqual(result.Params, []interface{}{"CVE-2023", "dependency"}) {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLFreeTextEscaping(t *testing.T) {
	node, err := Parse("100%_match")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if len(result.Params) != 1 || result.Params[0] != `100\%\_match` {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLMultipleStatusValues(t *testing.T) {
	node, err := Parse("status:detected,confirmed")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "status = ANY($1::vulnerability_status[])" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
	assertArrayValue(t, result.Params[0], `{"detected","confirmed"}`)
}

func TestToSQLSeverityMulti(t *testing.T) {
	node, err := Parse("severity:critical,high")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "severity::text = ANY($1::text[])" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
	assertArrayValue(t, result.Params[0], `{"critical","high"}`)
}

func TestToSQLLanguage(t *testing.T) {
	node, err := Parse("language:go")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "COALESCE(language, '') = $1" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 1 || result.Params[0] != "go" {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestToSQLComplexExpression(t *testing.T) {
	node, err := Parse("(type:sast OR type:secret) AND severity:critical,high AND file:main.go")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	expected := "((((type::text = $1 OR type::text = $2)) AND severity::text = ANY($3::text[])) AND COALESCE(file_path, '') ILIKE '%' || $4 || '%' ESCAPE '\\\\')"
	if result.Where != expected {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
	if len(result.Params) != 4 {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
	if result.Params[0] != "sast" || result.Params[1] != "secret" || result.Params[3] != "main.go" {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
	assertArrayValue(t, result.Params[2], `{"critical","high"}`)
}

func TestToSQLInvalidKey(t *testing.T) {
	node, err := Parse("owner:alice")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	_, err = ToSQL(node, 1)
	if err == nil || !strings.Contains(err.Error(), "unknown filter key") {
		t.Fatalf("expected unknown filter key error, got %v", err)
	}
}

func TestToSQLParameterOffset(t *testing.T) {
	node, err := Parse("type:sast AND status:detected")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 2)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if result.Where != "(type::text = $2 AND status = $3::vulnerability_status)" {
		t.Fatalf("unexpected where clause: %s", result.Where)
	}
}

func TestToSQLInjectionPrevention(t *testing.T) {
	raw := "type:sast';drop-table--"
	node, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	result, err := ToSQL(node, 1)
	if err != nil {
		t.Fatalf("ToSQL returned error: %v", err)
	}

	if strings.Contains(result.Where, "DROP TABLE") || strings.Contains(result.Where, "sast") {
		t.Fatalf("where clause contains raw value: %s", result.Where)
	}
	if len(result.Params) != 1 {
		t.Fatalf("unexpected params: %#v", result.Params)
	}
}

func TestParseFreeTextTokens(t *testing.T) {
	node, err := Parse("zlib")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	text, ok := node.(TextNode)
	if !ok {
		t.Fatalf("expected TextNode, got %T", node)
	}
	if text.Value != "zlib" {
		t.Fatalf("unexpected text value: %q", text.Value)
	}
}

func TestParseMultipleFreeTextTokensJoined(t *testing.T) {
	node, err := Parse("hello world")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	text, ok := node.(TextNode)
	if !ok {
		t.Fatalf("expected TextNode, got %T", node)
	}
	if text.Value != "hello world" {
		t.Fatalf("unexpected text value: %q", text.Value)
	}
}

func TestParseCaseInsensitiveOperators(t *testing.T) {
	inputs := []string{"type:sast and severity:high", "type:sast And severity:high"}
	for _, input := range inputs {
		node, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", input, err)
		}
		if _, ok := node.(AndNode); !ok {
			t.Fatalf("Parse(%q) expected AndNode, got %T", input, node)
		}
	}
}

func TestParseTrailingOR(t *testing.T) {
	_, err := Parse("type:sast OR")
	if err == nil || !strings.Contains(err.Error(), "OR must be followed") {
		t.Fatalf("expected trailing OR error, got %v", err)
	}
}

func TestParseConsecutiveOperators(t *testing.T) {
	_, err := Parse("type:sast AND AND severity:high")
	if err == nil {
		t.Fatal("expected error for consecutive operators")
	}
}

func TestToSQLRejectsExcessiveTreeDepth(t *testing.T) {
	node := Node(QualifierNode{Key: "type", Value: "sast"})
	for i := 0; i < maxDepth+1; i++ {
		node = GroupNode{Child: node}
	}

	_, err := ToSQL(node, 1)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("maximum depth of %d", maxDepth)) {
		t.Fatalf("expected maximum depth error, got %v", err)
	}
}

func assertArrayValue(t *testing.T, value interface{}, expected string) {
	t.Helper()
	valuer, ok := value.(driver.Valuer)
	if !ok {
		t.Fatalf("value does not implement driver.Valuer: %T", value)
	}
	raw, err := valuer.Value()
	if err != nil {
		t.Fatalf("Value() returned error: %v", err)
	}
	if raw != expected {
		t.Fatalf("unexpected array value: got %v want %s", raw, expected)
	}
}
