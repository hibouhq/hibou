package license

import (
	"strings"
	"unicode"
)

// SPDX license expressions are a real grammar, not a bag of words. Stated
// bottom-up, so precedence reads in the order the parser applies it:
//
//	term        := "(" expression ")" | id [ "WITH" id ]
//	conjunction := term ( "AND" term )*
//	disjunction := conjunction ( "OR" conjunction )*
//	expression  := disjunction
//
// The distinction is load-bearing for a policy gate. "MIT OR GPL-3.0-only" is
// dual-licensed — a consumer picks MIT and copyleft never applies. "MPL-2.0 AND
// MIT" means both obligations apply at once, so a copyleft-denying policy must
// fail it. Flattening the two into one list makes the gate silently under-block,
// and AND-expressions are common in real SBOMs (this repo's own apko SBOM emits
// "MPL-2.0 AND MIT").

const (
	opAnd = "AND"
	opOr  = "OR"
)

// exprNode is either a leaf id (exprID) or an operator with children (exprOp).
type exprNode interface{ isExprNode() }

type exprID struct{ raw string }

// exprUnparsed is an entry the grammar could not account for in full. It is a
// distinct node rather than a fallback to exprID because an exprID would be
// prefix-matched by Categorize: "MIT License AND GPL-3.0-only" starts with
// "mit", so treating the whole string as one id categorizes it PERMISSIVE and
// passes a copyleft-denying policy. Not understanding an expression has to mean
// unknown, which fails closed under deny_unknown.
type exprUnparsed struct{ raw string }

type exprOp struct {
	op       string
	children []exprNode
}

func (exprID) isExprNode()       {}
func (exprUnparsed) isExprNode() {}
func (exprOp) isExprNode()       {}

// parseExpression turns one license entry into a tree. Entries with no SPDX
// operator are returned whole rather than tokenized, so a free-form name like
// "SEE LICENSE IN LICENSE.txt" stays one unrecognized id instead of decaying
// into four meaningless words.
func parseExpression(expression string) exprNode {
	trimmed := strings.TrimSpace(expression)
	if trimmed == "" {
		return exprID{}
	}
	if !hasOperator(trimmed) {
		return exprID{raw: trimmed}
	}
	parser := &exprParser{tokens: tokenize(trimmed)}
	node := parser.parseOr()
	if node == nil {
		return exprUnparsed{raw: trimmed}
	}
	// Unconsumed tokens mean the grammar stopped early — a term followed by
	// anything that is not AND/OR ends the parse and the remainder is dropped.
	// That silently discards operands: "MIT License AND GPL-3.0-only" parses as
	// MIT alone. Anything not fully consumed is treated as not understood.
	if parser.pos < len(parser.tokens) {
		return exprUnparsed{raw: trimmed}
	}
	return node
}

// hasOperator reports whether the entry uses SPDX expression syntax at all.
func hasOperator(expression string) bool {
	if strings.ContainsAny(expression, "()") {
		return true
	}
	for _, field := range strings.Fields(expression) {
		switch strings.ToUpper(field) {
		case opAnd, opOr, "WITH":
			return true
		}
	}
	return false
}

// tokenize splits on whitespace and makes parentheses standalone tokens, so
// "(MPL-2.0 AND MIT)" parses without relying on the author spacing them out.
func tokenize(expression string) []string {
	tokens := make([]string, 0, 8)
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range expression {
		switch {
		case r == '(' || r == ')':
			flush()
			tokens = append(tokens, string(r))
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return tokens
}

type exprParser struct {
	tokens []string
	pos    int
}

func (p *exprParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *exprParser) next() string {
	token := p.peek()
	if token != "" {
		p.pos++
	}
	return token
}

func (p *exprParser) parseOr() exprNode {
	children := []exprNode{p.parseAnd()}
	for strings.EqualFold(p.peek(), opOr) {
		p.next()
		children = append(children, p.parseAnd())
	}
	if len(children) == 1 {
		return children[0]
	}
	return exprOp{op: opOr, children: children}
}

func (p *exprParser) parseAnd() exprNode {
	children := []exprNode{p.parseTerm()}
	for strings.EqualFold(p.peek(), opAnd) {
		p.next()
		children = append(children, p.parseTerm())
	}
	if len(children) == 1 {
		return children[0]
	}
	return exprOp{op: opAnd, children: children}
}

func (p *exprParser) parseTerm() exprNode {
	switch p.peek() {
	case "(":
		p.next()
		node := p.parseOr()
		if p.peek() == ")" {
			p.next()
		}
		return node
	case "", ")":
		// Malformed or exhausted input. Returning without consuming keeps the
		// caller's loop terminating instead of spinning on the same token.
		return exprID{}
	}
	id := p.next()
	if strings.EqualFold(p.peek(), "WITH") {
		p.next()
		if exception := p.peek(); exception != "" && exception != ")" && !isKeyword(exception) {
			id += " WITH " + p.next()
		}
	}
	return exprID{raw: id}
}

func isKeyword(token string) bool {
	switch strings.ToUpper(token) {
	case opAnd, opOr, "WITH":
		return true
	}
	return false
}

// NormalizeID canonicalizes one license id for grouping and display: collapsed
// whitespace, stripped wrapping parens, canonical keyword casing. Without it
// "MIT", "(MIT)" and "mit" count as three distinct licenses in any aggregate.
func NormalizeID(id string) string {
	normalized := strings.Join(strings.Fields(id), " ")
	for strings.HasPrefix(normalized, "(") && strings.HasSuffix(normalized, ")") && len(normalized) > 2 {
		// Only strip when the leading "(" is genuinely closed by the TRAILING
		// ")". For sibling groups — "(MIT OR Apache-2.0) AND (AGPL-3.0-only)" —
		// the first paren closes mid-string, and stripping the outer characters
		// produces unbalanced text that reparses to its first term alone,
		// silently dropping the denied operand.
		if !outerParensWrap(normalized) {
			break
		}
		normalized = strings.TrimSpace(normalized[1 : len(normalized)-1])
	}
	fields := strings.Fields(normalized)
	for i, field := range fields {
		if isKeyword(field) {
			fields[i] = strings.ToUpper(field)
		}
	}
	return strings.Join(fields, " ")
}

// outerParensWrap reports whether the first character's parenthesis is the one
// closed by the last character, i.e. whether the whole string is one group.
func outerParensWrap(value string) bool {
	depth := 0
	for i, r := range value {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				// Closed before the end: these are sibling groups, not a wrapper.
				return i == len(value)-1
			}
		}
	}
	return false
}

// NormalizeIDs canonicalizes a component's license list: each entry normalized,
// blanks dropped, duplicates removed, original order kept. Every surface that
// displays or compares licenses must go through this, or the same component
// renders different pills depending on which endpoint served it.
func NormalizeIDs(licenses []string) []string {
	normalized := make([]string, 0, len(licenses))
	seen := make(map[string]struct{}, len(licenses))
	for _, raw := range licenses {
		id := NormalizeID(raw)
		if id == "" {
			continue
		}
		// Dedup is case-insensitive because consumers compare case-folded;
		// the first spelling wins so display casing is still the SBOM's.
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, id)
	}
	return normalized
}
