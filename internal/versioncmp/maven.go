package versioncmp

import (
	"strings"
	"unicode"
)

// Maven compares Maven artifact versions.
type Maven struct{}

type mavenToken struct {
	numeric   bool
	qualifier bool
	value     int
	qual      string
}

var mavenQualifierRank = map[string]int{
	"alpha":     -5,
	"beta":      -4,
	"milestone": -3,
	"rc":        -2,
	"snapshot":  -1,
	"":          0,
	"sp":        1,
}

func (m *Maven) Compare(a, b string) int {
	ta := tokenizeMaven(a)
	tb := tokenizeMaven(b)
	max := len(ta)
	if len(tb) > max {
		max = len(tb)
	}
	for i := 0; i < max; i++ {
		var left, right mavenToken
		if i < len(ta) {
			left = ta[i]
		} else {
			rightHint := defaultMavenToken()
			if i < len(tb) {
				rightHint = tb[i]
			}
			left = mavenDefaultFor(rightHint)
		}
		if i < len(tb) {
			right = tb[i]
		} else {
			leftHint := defaultMavenToken()
			if i < len(ta) {
				leftHint = ta[i]
			}
			right = mavenDefaultFor(leftHint)
		}
		if cmp := compareMavenToken(left, right); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func (m *Maven) Valid(v string) bool {
	return strings.TrimSpace(v) != ""
}

func tokenizeMaven(v string) []mavenToken {
	v = strings.ToLower(strings.TrimSpace(v))
	tokens := make([]mavenToken, 0)
	lastSep := byte('.')
	prevWasQualifier := false
	for i := 0; i < len(v); {
		if v[i] == '.' || v[i] == '-' || v[i] == '_' {
			lastSep = v[i]
			i++
			continue
		}
		token, nextIndex, qualifier := nextMavenToken(v, i, lastSep, prevWasQualifier)
		tokens = append(tokens, token)
		prevWasQualifier = qualifier
		i = nextIndex
		lastSep = 0
	}
	return trimMavenTrailing(tokens)
}

func nextMavenToken(v string, start int, lastSep byte, prevWasQualifier bool) (mavenToken, int, bool) {
	end := start + 1
	numeric := unicode.IsDigit(rune(v[start]))
	for end < len(v) {
		if v[end] == '.' || v[end] == '-' || v[end] == '_' {
			break
		}
		if numeric != unicode.IsDigit(rune(v[end])) {
			break
		}
		end++
	}
	part := v[start:end]
	qualifier := lastSep == '-' || prevWasQualifier
	if isDigits(part) {
		return mavenToken{numeric: true, qualifier: qualifier, value: parseIntDefault(part)}, end, qualifier
	}
	return mavenToken{qualifier: true, qual: normalizeMavenQualifier(part)}, end, true
}

func normalizeMavenQualifier(q string) string {
	switch q {
	case "a", "alpha":
		return "alpha"
	case "b", "beta":
		return "beta"
	case "m", "milestone":
		return "milestone"
	case "cr", "rc":
		return "rc"
	case "ga", "final", "release":
		return ""
	default:
		return q
	}
}

func trimMavenTrailing(tokens []mavenToken) []mavenToken {
	end := len(tokens)
	for end > 0 {
		t := tokens[end-1]
		if t.numeric && !t.qualifier && t.value == 0 {
			end--
			continue
		}
		if !t.numeric && t.qual == "" {
			end--
			continue
		}
		break
	}
	return tokens[:end]
}

func compareMavenToken(a, b mavenToken) int {
	switch {
	case a.numeric && b.numeric:
		return cmpInts(a.value, b.value)
	case a.numeric && !b.numeric:
		return 1
	case !a.numeric && b.numeric:
		return -1
	default:
		ra, okA := mavenQualifierRank[a.qual]
		rb, okB := mavenQualifierRank[b.qual]
		if !okA {
			ra = 2
		}
		if !okB {
			rb = 2
		}
		if cmp := cmpInts(ra, rb); cmp != 0 {
			return cmp
		}
		if ra == 2 {
			return cmpStrings(a.qual, b.qual)
		}
		return 0
	}
}

func defaultMavenToken() mavenToken {
	return mavenToken{qual: ""}
}

func mavenDefaultFor(other mavenToken) mavenToken {
	if other.numeric {
		if other.qualifier {
			return mavenToken{qual: ""}
		}
		return mavenToken{numeric: true}
	}
	return mavenToken{qual: ""}
}
