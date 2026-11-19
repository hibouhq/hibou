package license

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Alternatives expands SPDX OR choices while retaining every AND obligation
// and WITH exception. Expansion is bounded for untrusted package metadata.
func Alternatives(expression string) ([][]string, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" || len(expression) > 4096 {
		return nil, errors.New("empty or oversized licence expression")
	}
	depth := 0
	for _, token := range tokenize(expression) {
		switch token {
		case "(":
			depth++
		case ")":
			depth--
		}
		if depth < 0 || depth > 32 {
			return nil, errors.New("invalid licence expression nesting")
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced licence expression")
	}
	p := &exprParser{tokens: tokenize(expression)}
	for i, token := range p.tokens {
		if strings.EqualFold(token, "WITH") && (i == 0 || i+1 == len(p.tokens) || isKeyword(p.tokens[i+1]) || p.tokens[i+1] == ")") {
			return nil, errors.New("missing licence exception")
		}
	}
	tree := p.parseOr()
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("invalid licence expression %q", expression)
	}
	return expandAlternatives(tree)
}

func expandAlternatives(node exprNode) ([][]string, error) {
	switch n := node.(type) {
	case exprID:
		fields := strings.Fields(n.raw)
		valid := len(fields) == 1 || len(fields) == 3 && fields[1] == "WITH"
		if !valid || isKeyword(fields[0]) || strings.HasSuffix(n.raw, " WITH") {
			return nil, fmt.Errorf("invalid licence operand %q", n.raw)
		}
		for _, field := range fields {
			for _, r := range field {
				if r > unicode.MaxASCII || !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(".-+:", r) {
					return nil, fmt.Errorf("invalid licence identifier %q", field)
				}
			}
		}
		return [][]string{{n.raw}}, nil
	case exprOp:
		var result [][]string
		if n.op == opAnd {
			result = [][]string{{}}
		}
		for _, child := range n.children {
			options, err := expandAlternatives(child)
			if err != nil {
				return nil, err
			}
			if n.op == opOr {
				result = append(result, options...)
			} else {
				var combined [][]string
				for _, a := range result {
					for _, b := range options {
						combined = append(combined, append(append([]string{}, a...), b...))
						if len(combined) > 64 {
							return nil, errors.New("licence expression exceeds 64 alternatives")
						}
					}
				}
				result = combined
			}
			if len(result) > 64 {
				return nil, errors.New("licence expression exceeds 64 alternatives")
			}
		}
		return result, nil
	default:
		return nil, errors.New("invalid licence expression")
	}
}
