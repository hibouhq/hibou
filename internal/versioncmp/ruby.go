package versioncmp

import (
	"strings"
	"unicode"
)

// RubyGems compares Gem::Version-style versions.
type RubyGems struct{}

type rubyToken struct {
	numeric bool
	value   int
	text    string
}

func (r *RubyGems) Compare(a, b string) int {
	ta := parseRubyTokens(a)
	tb := parseRubyTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if cmp, done := compareRubyTokenAt(ta, tb, i); done {
			return cmp
		}
	}
	return 0
}

func (r *RubyGems) Valid(v string) bool {
	return strings.TrimSpace(v) != ""
}

func parseRubyTokens(v string) []rubyToken {
	v = strings.ToLower(strings.TrimSpace(v))
	parts := strings.Split(v, ".")
	tokens := make([]rubyToken, 0)
	for _, part := range parts {
		for part != "" {
			token, rest := nextRubyToken(part)
			tokens = append(tokens, token)
			part = rest
		}
	}
	for len(tokens) > 0 && tokens[len(tokens)-1].numeric && tokens[len(tokens)-1].value == 0 {
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
}

func compareRubyTokenAt(ta, tb []rubyToken, index int) (int, bool) {
	if index >= len(ta) {
		return rubyCompareMissing(tb[index:]), true
	}
	if index >= len(tb) {
		return -rubyCompareMissing(ta[index:]), true
	}
	cmp := compareRubyTokenPair(ta[index], tb[index])
	return cmp, cmp != 0
}

func compareRubyTokenPair(left, right rubyToken) int {
	switch {
	case left.numeric && right.numeric:
		return cmpInts(left.value, right.value)
	case left.numeric && !right.numeric:
		return 1
	case !left.numeric && right.numeric:
		return -1
	default:
		return cmpStrings(left.text, right.text)
	}
}

func nextRubyToken(part string) (rubyToken, string) {
	end := 0
	numeric := unicode.IsDigit(rune(part[0]))
	for end < len(part) {
		r := rune(part[end])
		if numeric && !unicode.IsDigit(r) {
			break
		}
		if !numeric && !unicode.IsLetter(r) {
			break
		}
		end++
	}
	segment := part[:end]
	if numeric {
		return rubyToken{numeric: true, value: parseIntDefault(segment)}, part[end:]
	}
	return rubyToken{text: segment}, part[end:]
}

func rubyCompareMissing(remaining []rubyToken) int {
	for _, token := range remaining {
		if token.numeric {
			if token.value != 0 {
				return -1
			}
			continue
		}
		return 1
	}
	return 0
}
