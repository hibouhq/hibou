package filterquery

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/cwe"
)

type TokenType int

const (
	TokenQualifier TokenType = iota
	TokenAnd
	TokenOr
	TokenLParen
	TokenRParen
	TokenText
	TokenEOF
)

type token struct {
	typ   TokenType
	value string
	start int
	end   int
}

type Node interface{ nodeType() string }

type QualifierNode struct {
	Key   string
	Value string
	// Negated is GitHub's exclusion: -type:dependency keeps every row the
	// qualifier would NOT match.
	Negated bool
}

func (QualifierNode) nodeType() string { return "qualifier" }

type AndNode struct {
	Left, Right Node
}

func (AndNode) nodeType() string { return "and" }

type OrNode struct {
	Left, Right Node
}

func (OrNode) nodeType() string { return "or" }

type GroupNode struct {
	Child Node
}

func (GroupNode) nodeType() string { return "group" }

type TextNode struct {
	Value string
}

func (TextNode) nodeType() string { return "text" }

var AllowedColumns = map[string]string{
	"type":     "type",
	"severity": "severity",
	"status":   "status",
	"scanner":  "scanner_name",
	"tool":     "scanner_name",
	"language": "language",
	"file":     "file_path",
	"origin":   "origin",
	// Revoking a token has to be able to pull back everything it filed, so the
	// token id is a first-class filter: q=agent:<token-uuid>.
	"agent": "origin_api_key_id",
	// ADR-023 decision filters, resolved against the acceptance LEFT JOIN
	// (alias fa) that the dynamic list query always carries.
	"acceptance": "fa.reason_kind",
	"label":      "fa.labels",
	// Known-exploited membership (ADR-032): resolved against the kev_entries
	// mirror, not a column — see exploitedQualifierToSQL.
	"exploited": "",
	// CWE (ADR-037): resolved against the finding_cwes view — see CWESQL.
	cwe.KindExact: "",
	cwe.KindTree:  "",
	cwe.KindSet:   "",
	// View 1400 categories (ADR-037): cwe-category:injection.
	cwe.KindCategory: "",
	// Risk metrics (ADR-038 §6): cvss:>=7, epss:>=10%, epss-percentile:>=0.95,
	// and :none for unscored. CVSS is the rating the finding uses; EPSS is
	// resolved against the daily mirror — see riskQualifierToSQL.
	"cvss":            "v.cvss_score",
	"epss":            "",
	"epss-percentile": "",
}

const maxDepth = 16

type SQLResult struct {
	Where  string
	Params []interface{}
}

func Parse(input string) (Node, error) {
	parser := newParser(input)
	return parser.parse()
}

func ToSQL(node Node, startParam int) (SQLResult, error) {
	if node == nil {
		return SQLResult{}, nil
	}

	where, params, _, err := buildSQL(node, startParam, 0)
	if err != nil {
		return SQLResult{}, err
	}

	return SQLResult{Where: where, Params: params}, nil
}

type parser struct {
	tokens []token
	pos    int
}

func newParser(input string) *parser {
	return &parser{tokens: lex(input)}
}

func (p *parser) parse() (Node, error) {
	if p.peek().typ == TokenEOF {
		return nil, nil
	}

	node, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}

	if p.peek().typ != TokenEOF {
		if p.peek().typ == TokenRParen {
			return nil, fmt.Errorf("unmatched closing parenthesis at %d", p.peek().start)
		}
		return nil, fmt.Errorf("unexpected token %q at %d", p.peek().value, p.peek().start)
	}

	return node, nil
}

func (p *parser) parseOr(depth int) (Node, error) {
	left, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}

	for p.match(TokenOr) {
		right, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		if right == nil {
			return nil, errors.New("OR must be followed by an expression")
		}
		left = OrNode{Left: left, Right: right}
	}

	return left, nil
}

func (p *parser) parseAnd(depth int) (Node, error) {
	left, err := p.parsePrimary(depth)
	if err != nil {
		return nil, err
	}

	for {
		next := p.peek().typ
		explicitAnd := p.match(TokenAnd)
		implicitAnd := !explicitAnd && (next == TokenQualifier || next == TokenText || next == TokenLParen)
		if !explicitAnd && !implicitAnd {
			return left, nil
		}

		right, err := p.parsePrimary(depth)
		if err != nil {
			return nil, err
		}
		if right == nil {
			return nil, errors.New("AND must be followed by an expression")
		}
		left = AndNode{Left: left, Right: right}
	}
}

func (p *parser) parsePrimary(depth int) (Node, error) {
	switch p.peek().typ {
	case TokenQualifier:
		tok := p.consume()
		separator := strings.Index(tok.value, ":")
		key := strings.ToLower(strings.TrimSpace(tok.value[:separator]))
		value := strings.ToLower(strings.TrimSpace(tok.value[separator+1:]))
		negated := strings.HasPrefix(key, "-")
		key = strings.TrimPrefix(key, "-")
		if key == "" || value == "" {
			return nil, fmt.Errorf("invalid qualifier %q", tok.value)
		}
		return QualifierNode{Key: key, Value: value, Negated: negated}, nil
	case TokenLParen:
		if depth >= maxDepth {
			return nil, fmt.Errorf("filter nesting exceeds maximum depth of %d", maxDepth)
		}
		open := p.consume()
		if p.match(TokenRParen) {
			return nil, fmt.Errorf("empty parentheses at %d", open.start)
		}
		child, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if !p.match(TokenRParen) {
			return nil, fmt.Errorf("missing closing parenthesis at %d", open.start)
		}
		return GroupNode{Child: child}, nil
	case TokenText:
		first := p.consume()
		// A bare "CWE-79" is what people paste; it means the CWE, not a title
		// substring (ADR-037 §5).
		if bareCWEPattern.MatchString(first.value) {
			return QualifierNode{Key: cwe.KindExact, Value: strings.ToLower(first.value)}, nil
		}
		parts := []string{first.value}
		for p.peek().typ == TokenText && !bareCWEPattern.MatchString(p.peek().value) {
			parts = append(parts, p.consume().value)
		}
		return TextNode{Value: strings.Join(parts, " ")}, nil
	case TokenRParen:
		return nil, fmt.Errorf("unmatched closing parenthesis at %d", p.peek().start)
	case TokenEOF:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected token %q at %d", p.peek().value, p.peek().start)
	}
}

func (p *parser) peek() token {
	return p.tokens[p.pos]
}

func (p *parser) consume() token {
	tok := p.tokens[p.pos]
	p.pos++
	return tok
}

func (p *parser) match(typ TokenType) bool {
	if p.peek().typ != typ {
		return false
	}
	p.pos++
	return true
}

func lex(input string) []token {
	tokens := make([]token, 0, len(input)+1)
	for i := 0; i < len(input); {
		if isSpace(input[i]) {
			i++
			continue
		}

		switch input[i] {
		case '(':
			tokens = append(tokens, token{typ: TokenLParen, value: "(", start: i, end: i + 1})
			i++
			continue
		case ')':
			tokens = append(tokens, token{typ: TokenRParen, value: ")", start: i, end: i + 1})
			i++
			continue
		}

		start := i
		for i < len(input) && !isSpace(input[i]) && input[i] != '(' && input[i] != ')' {
			i++
		}

		value := input[start:i]
		upper := strings.ToUpper(value)
		switch {
		case strings.Contains(value, ":"):
			tokens = append(tokens, token{typ: TokenQualifier, value: value, start: start, end: i})
		case upper == "AND":
			tokens = append(tokens, token{typ: TokenAnd, value: value, start: start, end: i})
		case upper == "OR":
			tokens = append(tokens, token{typ: TokenOr, value: value, start: start, end: i})
		default:
			tokens = append(tokens, token{typ: TokenText, value: value, start: start, end: i})
		}
	}

	tokens = append(tokens, token{typ: TokenEOF, start: len(input), end: len(input)})
	return tokens
}

func buildSQL(node Node, param int, depth int) (string, []interface{}, int, error) {
	if depth > maxDepth {
		return "", nil, param, fmt.Errorf("filter nesting exceeds maximum depth of %d", maxDepth)
	}

	switch typed := node.(type) {
	case QualifierNode:
		where, params, next, err := qualifierToSQL(typed, param)
		if err != nil || !typed.Negated {
			return where, params, next, err
		}
		// COALESCE: a predicate over a NULL column (no acceptance row, no
		// language) is NULL, and NOT NULL would drop the row instead of
		// keeping it — "-acceptance:risk" must keep open findings.
		return "NOT COALESCE((" + where + "), FALSE)", params, next, nil
	case TextNode:
		return textNodeToSQL(typed, param), []interface{}{escapeLikeFragment(typed.Value)}, param + 1, nil
	case AndNode:
		return buildBinarySQL("AND", typed.Left, typed.Right, param, depth)
	case OrNode:
		return buildBinarySQL("OR", typed.Left, typed.Right, param, depth)
	case GroupNode:
		childWhere, params, nextParam, err := buildSQL(typed.Child, param, depth+1)
		if err != nil {
			return "", nil, param, err
		}
		return fmt.Sprintf("(%s)", childWhere), params, nextParam, nil
	default:
		return "", nil, param, fmt.Errorf("unsupported node type %T", node)
	}
}

func textNodeToSQL(node TextNode, param int) string {
	return fmt.Sprintf("(title ILIKE '%%' || $%d || '%%' ESCAPE '\\' OR primary_identifier_value ILIKE '%%' || $%d || '%%' ESCAPE '\\')", param, param)
}

func buildBinarySQL(operator string, left Node, right Node, param int, depth int) (string, []interface{}, int, error) {
	leftWhere, leftParams, nextParam, err := buildSQL(left, param, depth)
	if err != nil {
		return "", nil, param, err
	}
	rightWhere, rightParams, nextParam, err := buildSQL(right, nextParam, depth)
	if err != nil {
		return "", nil, param, err
	}
	return fmt.Sprintf("(%s %s %s)", leftWhere, operator, rightWhere), append(leftParams, rightParams...), nextParam, nil
}

func qualifierToSQL(node QualifierNode, param int) (string, []interface{}, int, error) {
	column, ok := AllowedColumns[node.Key]
	if !ok {
		return "", nil, param, fmt.Errorf("unknown filter key %q", node.Key)
	}

	values := splitValues(node.Value)
	if len(values) == 0 {
		return "", nil, param, fmt.Errorf("filter %q requires a value", node.Key)
	}

	switch node.Key {
	case cwe.KindExact, cwe.KindTree, cwe.KindSet, cwe.KindCategory:
		selector, err := cwe.ParseSelector(node.Key, values)
		if err != nil {
			return "", nil, param, err
		}
		where, params, next := CWESQL("v", selector, param)
		return where, params, next, nil
	case "cvss", "epss", "epss-percentile":
		return riskQualifierToSQL(node.Key, values, param)
	case "exploited":
		return exploitedQualifierToSQL(values, param)
	case "acceptance":
		return acceptanceQualifierToSQL(values, param)
	case "label":
		return labelQualifierToSQL(values, param)
	case "file":
		return fileQualifierToSQL(column, values, param), fileQualifierParams(values), param + len(values), nil
	case "status":
		return singleOrArraySQL(column, values, param, "%s = $%d::vulnerability_status", "%s = ANY($%d::vulnerability_status[])")
	case "severity":
		return singleOrArraySQL(column, values, param, "%s::text = $%d", "%s::text = ANY($%d::text[])")
	case "language":
		return singleOrArraySQL("COALESCE("+column+", '')", values, param, "%s = $%d", "%s = ANY($%d::text[])")
	case "type", "origin", "agent":
		return singleOrArraySQL(column, values, param, "%s::text = $%d", "%s::text = ANY($%d::text[])")
	default:
		return singleOrArraySQL(column, values, param, "%s = $%d", "%s = ANY($%d::text[])")
	}
}

// bareCWEPattern recognizes a free-text token that is a CWE identifier.
var bareCWEPattern = regexp.MustCompile(`(?i)^cwe-[0-9]+$`)

// CWESQL compiles a selector into a predicate over the vulnerabilities row
// aliased alias. It encodes the same four sources as the finding_cwes view
// (rule, advisory, per-finding assertion, finding type) but against the
// row's own columns, because the shape decides how it scales:
//
//   - an id set compiles to uncorrelated IN (SELECT … WHERE cwe_id = ANY($n))
//     branches. Under the OR that joins them Postgres cannot turn sublinks
//     into joins, but an uncorrelated IN becomes a hashed SubPlan: computed
//     once from the covering (cwe_id, …) index, then one hash probe per row.
//     A correlated EXISTS through the view would instead run per row and
//     re-read vulnerabilities inside it.
//   - "any"/"none" have no id to drive from, so they probe the claim tables'
//     primary keys per row (index-only, bounded) instead of hashing whole tables.
//   - the secret → CWE-798 mapping is folded in Go: no subquery at all.
//
// The selector arrives expanded (tree descendants and set members resolved
// from the embedded catalog), so every qualifier is one membership test.
func CWESQL(alias string, selector cwe.Selector, param int) (string, []interface{}, int) {
	parts := make([]string, 0, 3)
	params := make([]interface{}, 0, 1)
	next := param
	if len(selector.IDs) > 0 {
		ids := fmt.Sprintf("$%d::int[]", next)
		params = append(params, pq.Array(selector.IDs))
		next++
		branches := []string{
			fmt.Sprintf("%s.rule_ref_id IN (SELECT scan_rule_id FROM scan_rule_cwes WHERE cwe_id = ANY(%s))", alias, ids),
			fmt.Sprintf("%s.advisory_id IN (SELECT advisory_id FROM advisory_cwes WHERE cwe_id = ANY(%s))", alias, ids),
			fmt.Sprintf("(%s.repo_id, %s.fingerprint) IN (SELECT repo_id, fingerprint FROM finding_cwe_assertions WHERE cwe_id = ANY(%s) AND source = 'sarif_result')", alias, alias, ids),
			fmt.Sprintf("(%s.type = 'manual' AND (%s.repo_id, %s.fingerprint) IN (SELECT repo_id, fingerprint FROM finding_cwe_assertions WHERE cwe_id = ANY(%s) AND source = 'declared'))", alias, alias, alias, ids),
		}
		if slices.Contains(selector.IDs, secretCWE) {
			branches = append(branches, alias+".type = 'secret'")
		}
		parts = append(parts, "("+strings.Join(branches, " OR ")+")")
	}
	if selector.Any || selector.None {
		carries := carriesAnyCWESQL(alias)
		if selector.Any {
			parts = append(parts, carries)
		}
		if selector.None {
			parts = append(parts, "NOT "+carries)
		}
	}
	if len(parts) == 0 {
		// A selector that expands to nothing (an empty set) matches nothing.
		return "FALSE", params, next
	}
	if len(parts) == 1 {
		return parts[0], params, next
	}
	return "(" + strings.Join(parts, " OR ") + ")", params, next
}

// secretCWE is the CWE a leaked secret carries by definition (the view's
// 'type' branch).
const secretCWE = 798

func carriesAnyCWESQL(alias string) string {
	return fmt.Sprintf("(EXISTS (SELECT 1 FROM scan_rule_cwes WHERE scan_rule_id = %[1]s.rule_ref_id)"+
		" OR EXISTS (SELECT 1 FROM advisory_cwes WHERE advisory_id = %[1]s.advisory_id)"+
		" OR EXISTS (SELECT 1 FROM finding_cwe_assertions fa WHERE fa.repo_id = %[1]s.repo_id AND fa.fingerprint = %[1]s.fingerprint"+
		" AND (fa.source = 'sarif_result' OR %[1]s.type = 'manual'))"+
		" OR %[1]s.type = 'secret')", alias)
}

// exploitedSQL is the known-exploited membership test the gate blocks on
// (ADR-032): the finding's advisory — by id+aliases, or bare identifier — is
// on a mirrored exploited catalog. Scoped to advisory-backed finding types;
// parameterless (closed true/false vocabulary). The alias v matches the
// dynamic list query this filter is compiled for.
const exploitedSQL = `(v.type IN ('dependency','container','malware') AND (` +
	`EXISTS (SELECT 1 FROM kev_entries k WHERE k.cve_id = upper(v.primary_identifier_value))` +
	` OR EXISTS (SELECT 1 FROM advisories adv LEFT JOIN advisory_aliases al ON al.advisory_id = adv.id` +
	` JOIN kev_entries k2 ON k2.cve_id IN (upper(adv.canonical_id), upper(al.alias))` +
	` WHERE adv.id = v.advisory_id)))`

// epssSQL is a finding's EPSS score or percentile: the highest among its
// identifier and its advisory's aliases (ADR-038 §4).
//
// Two primary-key lookups under GREATEST (which skips NULLs), not one lookup
// under OR: an OR across the identifier and the aliases defeats the index and
// scans the whole ~300k-row mirror per finding.
func epssSQL(column string) string {
	return `GREATEST((SELECT e.` + column + ` FROM epss_scores e WHERE e.cve_id = upper(v.primary_identifier_value)),` +
		` (SELECT max(e.` + column + `) FROM advisory_aliases al JOIN epss_scores e ON e.cve_id = upper(al.alias) WHERE al.advisory_id = v.advisory_id))`
}

// riskQualifierToSQL compiles cvss:, epss: and epss-percentile:. The value is
// a comparison (">=7", "<0.1", "=9.8"; a bare number means >=), "none" or
// "any". EPSS values may be written as percentages ("10%").
func riskQualifierToSQL(key string, values []string, param int) (string, []interface{}, int, error) {
	if len(values) != 1 {
		return "", nil, param, fmt.Errorf("%s takes a single comparison such as %s:>=7", key, key)
	}
	expression, ceiling := "v.cvss_score", 10.0
	switch key {
	case "epss":
		expression, ceiling = epssSQL("score"), 1
	case "epss-percentile":
		expression, ceiling = epssSQL("percentile"), 1
	}
	switch values[0] {
	case "none":
		return expression + " IS NULL", nil, param, nil
	case "any":
		return expression + " IS NOT NULL", nil, param, nil
	}
	operator, number, err := ParseComparison(values[0], ceiling < 10)
	if err != nil {
		return "", nil, param, fmt.Errorf("%s: %w", key, err)
	}
	if number < 0 || number > ceiling {
		return "", nil, param, fmt.Errorf("%s must be between 0 and %g", key, ceiling)
	}
	return fmt.Sprintf("%s %s $%d::numeric", expression, operator, param), []interface{}{number}, param + 1, nil
}

// ParseComparison reads ">=7", ">0.5", "<=10%", "=9.8" or a bare number
// (meaning >=). percent allows a "%" suffix, divided by 100.
func ParseComparison(raw string, percent bool) (string, float64, error) {
	operator := ">="
	for _, candidate := range []string{">=", "<=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(raw, candidate); ok {
			operator, raw = candidate, rest
			break
		}
	}
	scale := 1.0
	if percent {
		if rest, ok := strings.CutSuffix(raw, "%"); ok {
			raw, scale = rest, 100
		}
	}
	number, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not a number", raw)
	}
	return operator, number / scale, nil
}

func exploitedQualifierToSQL(values []string, param int) (string, []interface{}, int, error) {
	if len(values) != 1 {
		return "", nil, param, errors.New("exploited takes a single true/false value")
	}
	switch values[0] {
	case "true", "yes":
		return exploitedSQL, nil, param, nil
	case "false", "no":
		return "NOT " + exploitedSQL, nil, param, nil
	default:
		return "", nil, param, fmt.Errorf("exploited must be true or false (got %q)", values[0])
	}
}

// acceptanceQualifierToSQL maps the ADR-023 decision filter: risk | fp |
// none (open). Values are a closed vocabulary, so the SQL is parameterless.
func acceptanceQualifierToSQL(values []string, param int) (string, []interface{}, int, error) {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		switch value {
		case "risk", "risk_accepted":
			parts = append(parts, "fa.reason_kind = 'risk_accepted'")
		case "fp", "false_positive":
			parts = append(parts, "fa.reason_kind = 'false_positive'")
		case "none", "open":
			parts = append(parts, "fa.id IS NULL")
		case "any", "accepted":
			parts = append(parts, "fa.id IS NOT NULL")
		case "disputed":
			// ADR-026: the suppression is contested — resolved against the
			// finding_disputes LEFT JOIN (fd), not the acceptance row.
			parts = append(parts, "fd.id IS NOT NULL")
		default:
			return "", nil, param, fmt.Errorf("acceptance must be one of risk, fp, accepted, open, disputed (got %q)", value)
		}
	}
	if len(parts) == 1 {
		return parts[0], nil, param, nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil, param, nil
}

func labelQualifierToSQL(values []string, param int) (string, []interface{}, int, error) {
	parts := make([]string, 0, len(values))
	params := make([]interface{}, 0, len(values))
	for index, value := range values {
		parts = append(parts, fmt.Sprintf("$%d = ANY(fa.labels)", param+index))
		params = append(params, value)
	}
	if len(parts) == 1 {
		return parts[0], params, param + 1, nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", params, param + len(values), nil
}

func fileQualifierToSQL(column string, values []string, param int) string {
	if len(values) == 1 {
		return fmt.Sprintf("COALESCE(%s, '') ILIKE '%%' || $%d || '%%' ESCAPE '\\'", column, param)
	}
	parts := make([]string, 0, len(values))
	for index := range values {
		parts = append(parts, fmt.Sprintf("COALESCE(%s, '') ILIKE '%%' || $%d || '%%' ESCAPE '\\'", column, param+index))
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func fileQualifierParams(values []string) []interface{} {
	params := make([]interface{}, 0, len(values))
	for _, value := range values {
		params = append(params, escapeLikeFragment(value))
	}
	return params
}

func singleOrArraySQL(column string, values []string, param int, singleFmt string, arrayFmt string) (string, []interface{}, int, error) {
	if len(values) == 1 {
		return fmt.Sprintf(singleFmt, column, param), []interface{}{values[0]}, param + 1, nil
	}
	return fmt.Sprintf(arrayFmt, column, param), []interface{}{pq.Array(values)}, param + 1, nil
}

func splitValues(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.ToLower(strings.TrimSpace(part))
		if normalized == "" {
			continue
		}
		values = append(values, normalized)
	}
	return values
}

func escapeLikeFragment(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.ReplaceAll(trimmed, `\`, `\\`)
	trimmed = strings.ReplaceAll(trimmed, `%`, `\%`)
	trimmed = strings.ReplaceAll(trimmed, `_`, `\_`)
	return trimmed
}

func isSpace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\n' || char == '\r'
}
