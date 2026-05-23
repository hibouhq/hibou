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
		parsed.revision = parseIntDefault(v[idx+2:], 0)
	}
	for _, suffix := range []string{"alpha", "beta", "pre", "rc", "p"} {
		marker := "_" + suffix
		if idx := strings.Index(parsed.base, marker); idx >= 0 {
			parsed.suffix = suffix
			parsed.suffixNo = parseIntDefault(parsed.base[idx+len(marker):], 0)
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

		if ai < len(a) && a[ai] == '~' || bi < len(b) && b[bi] == '~' {
			switch {
			case ai < len(a) && a[ai] == '~' && bi < len(b) && b[bi] == '~':
				ai++
				bi++
				continue
			case ai < len(a) && a[ai] == '~':
				return -1
			default:
				return 1
			}
		}

		if ai >= len(a) && bi >= len(b) {
			return 0
		}
		if ai >= len(a) {
			return -1
		}
		if bi >= len(b) {
			return 1
		}

		aNum := unicode.IsDigit(rune(a[ai]))
		bNum := unicode.IsDigit(rune(b[bi]))
		switch {
		case aNum && !bNum:
			return 1
		case !aNum && bNum:
			return -1
		}

		aSeg, nextA := apkReadSegment(a, ai, aNum)
		bSeg, nextB := apkReadSegment(b, bi, bNum)
		var cmp int
		if aNum {
			cmp = rpmCompareNumeric(aSeg, bSeg)
		} else {
			cmp = cmpStrings(strings.ToLower(aSeg), strings.ToLower(bSeg))
		}
		if cmp != 0 {
			return cmp
		}
		ai = nextA
		bi = nextB
	}
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
