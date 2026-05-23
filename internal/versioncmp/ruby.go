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
		if i >= len(ta) {
			return rubyCompareMissing(tb[i:])
		}
		if i >= len(tb) {
			return -rubyCompareMissing(ta[i:])
		}
		left := ta[i]
		right := tb[i]
		switch {
		case left.numeric && right.numeric:
			if cmp := cmpInts(left.value, right.value); cmp != 0 {
				return cmp
			}
		case left.numeric && !right.numeric:
			return 1
		case !left.numeric && right.numeric:
			return -1
		default:
			if cmp := cmpStrings(left.text, right.text); cmp != 0 {
				return cmp
			}
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
			start := 0
			numeric := unicode.IsDigit(rune(part[0]))
			for start < len(part) {
				r := rune(part[start])
				if numeric && !unicode.IsDigit(r) {
					break
				}
				if !numeric && !unicode.IsLetter(r) {
					break
				}
				start++
			}
			seg := part[:start]
			if numeric {
				tokens = append(tokens, rubyToken{numeric: true, value: parseIntDefault(seg, 0)})
			} else {
				tokens = append(tokens, rubyToken{text: seg})
			}
			part = part[start:]
		}
	}
	for len(tokens) > 0 && tokens[len(tokens)-1].numeric && tokens[len(tokens)-1].value == 0 {
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
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
