package versioncmp

import (
	"strings"
	"unicode"
)

// APK compares Alpine package versions.
type APK struct{}

type apkVersion struct {
	base     string
	suffix   string
	suffixNo int
	revision int
}

var apkSuffixRank = map[string]int{
	"alpha": -4,
	"beta":  -3,
	"pre":   -2,
	"rc":    -1,
	"":      0,
	"p":     1,
}

func (a *APK) Compare(left, right string) int {
	lv := parseAPKVersion(left)
	rv := parseAPKVersion(right)

	if cmp := apkCompareBase(lv.base, rv.base); cmp != 0 {
		return cmp
	}
	if cmp := cmpInts(apkSuffixRank[lv.suffix], apkSuffixRank[rv.suffix]); cmp != 0 {
		return cmp
	}
	if cmp := cmpInts(lv.suffixNo, rv.suffixNo); cmp != 0 {
		return cmp
	}
	return cmpInts(lv.revision, rv.revision)
}

func (a *APK) Valid(v string) bool {
	return strings.TrimSpace(v) != ""
}

func parseAPKVersion(v string) apkVersion {
	v = strings.TrimSpace(v)
	parsed := apkVersion{base: v}
	if idx := strings.LastIndex(v, "-r"); idx >= 0 {
		parsed.base = v[:idx]
		parsed.revision = parseIntDefault(v[idx+2:])
	}
	for _, suffix := range []string{"alpha", "beta", "pre", "rc", "p"} {
		marker := "_" + suffix
		if idx := strings.Index(parsed.base, marker); idx >= 0 {
			parsed.suffix = suffix
			parsed.suffixNo = parseIntDefault(parsed.base[idx+len(marker):])
			parsed.base = parsed.base[:idx]
			break
		}
	}
	return parsed
}

func apkCompareBase(a, b string) int {
	ai, bi := 0, 0
	for {
		ai = apkSkipSeparators(a, ai)
		bi = apkSkipSeparators(b, bi)

		if cmp, nextA, nextB, handled := rpmCompareTilde(a, b, ai, bi); handled {
			if cmp != 0 {
				return cmp
			}
			ai = nextA
			bi = nextB
			continue
		}

		if cmp, done := apkCompareRemainder(a, b, ai, bi); done {
			return cmp
		}

		cmp, nextA, nextB := apkCompareSegmentPair(a, b, ai, bi)
		if cmp != 0 {
			return cmp
		}
		ai = nextA
		bi = nextB
	}
}

func apkCompareRemainder(a, b string, ai, bi int) (int, bool) {
	if ai >= len(a) && bi >= len(b) {
		return 0, true
	}
	if ai >= len(a) {
		return -1, true
	}
	if bi >= len(b) {
		return 1, true
	}
	return 0, false
}

func apkCompareSegmentPair(a, b string, ai, bi int) (int, int, int) {
	aNum := unicode.IsDigit(rune(a[ai]))
	bNum := unicode.IsDigit(rune(b[bi]))
	switch {
	case aNum && !bNum:
		return 1, ai, bi
	case !aNum && bNum:
		return -1, ai, bi
	}
	aSeg, nextA := apkReadSegment(a, ai, aNum)
	bSeg, nextB := apkReadSegment(b, bi, bNum)
	if aNum {
		return rpmCompareNumeric(aSeg, bSeg), nextA, nextB
	}
	return cmpStrings(strings.ToLower(aSeg), strings.ToLower(bSeg)), nextA, nextB
}

func apkSkipSeparators(s string, idx int) int {
	for idx < len(s) {
		ch := s[idx]
		if unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch)) || ch == '~' {
			break
		}
		idx++
	}
	return idx
}

func apkReadSegment(s string, idx int, numeric bool) (string, int) {
	start := idx
	for idx < len(s) {
		r := rune(s[idx])
		if numeric {
			if !unicode.IsDigit(r) {
				break
			}
		} else if !unicode.IsLetter(r) {
			break
		}
		idx++
	}
	return s[start:idx], idx
}
