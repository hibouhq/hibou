package filterquery

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
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
		if key == "" || value == "" {
			return nil, fmt.Errorf("invalid qualifier %q", tok.value)
		}
		return QualifierNode{Key: key, Value: value}, nil
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
		parts := []string{p.consume().value}
		for p.peek().typ == TokenText {
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
		return qualifierToSQL(typed, param)
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
		default:
			return "", nil, param, fmt.Errorf("acceptance must be one of risk, fp, accepted, open (got %q)", value)
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
