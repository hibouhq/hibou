package versioncmp

import (
	"strings"
	"unicode"
)

// Debian compares dpkg epoch:upstream-debian_revision version strings.
type Debian struct{}

type debianVersion struct {
	epoch    int
	upstream string
	revision string
}

func (d *Debian) Compare(a, b string) int {
	av := parseDebianVersion(a)
	bv := parseDebianVersion(b)

	if cmp := cmpInts(av.epoch, bv.epoch); cmp != 0 {
		return cmp
	}
	if cmp := debianComparePart(av.upstream, bv.upstream); cmp != 0 {
		return cmp
	}
	if av.revision == "" && bv.revision != "" {
		return -1
	}
	if av.revision != "" && bv.revision == "" {
		return 1
	}
	return debianComparePart(av.revision, bv.revision)
}

func (d *Debian) Valid(v string) bool {
	return strings.TrimSpace(v) != ""
}

func parseDebianVersion(v string) debianVersion {
	v = strings.TrimSpace(v)
	parsed := debianVersion{}
	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		parsed.epoch = parseIntDefault(v[:idx])
		v = v[idx+1:]
	}
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		parsed.upstream = v[:idx]
		parsed.revision = v[idx+1:]
	} else {
		parsed.upstream = v
	}
	return parsed
}

func debianComparePart(a, b string) int {
	for a != "" || b != "" {
		aNon, aRest := debianTakeWhile(a, func(r rune) bool { return !unicode.IsDigit(r) })
		bNon, bRest := debianTakeWhile(b, func(r rune) bool { return !unicode.IsDigit(r) })
		if cmp := debianCompareNonDigit(aNon, bNon); cmp != 0 {
			return cmp
		}
		a = aRest
		b = bRest

		aDig, aRest := debianTakeWhile(a, unicode.IsDigit)
		bDig, bRest := debianTakeWhile(b, unicode.IsDigit)
		if cmp := debianCompareDigits(aDig, bDig); cmp != 0 {
			return cmp
		}
		a = aRest
		b = bRest
	}
	return 0
}

func debianTakeWhile(s string, fn func(rune) bool) (string, string) {
	idx := 0
	for idx < len(s) && fn(rune(s[idx])) {
		idx++
	}
	return s[:idx], s[idx:]
}

func debianCompareNonDigit(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		var ca, cb byte
		if len(a) > 0 {
			ca = a[0]
			a = a[1:]
		}
		if len(b) > 0 {
			cb = b[0]
			b = b[1:]
		}
		if cmp := cmpInts(debianOrder(ca), debianOrder(cb)); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func debianOrder(ch byte) int {
	switch {
	case ch == '~':
		return -1
	case ch == 0:
		return 0
	case unicode.IsLetter(rune(ch)):
		return int(ch)
	default:
		return int(ch) + 256
	}
}

func debianCompareDigits(a, b string) int {
	a = trimLeadingZeros(a)
	b = trimLeadingZeros(b)
	if a == "0" && b == "0" {
		return 0
	}
	if cmp := cmpInts(len(a), len(b)); cmp != 0 {
		return cmp
	}
	return cmpStrings(a, b)
}
