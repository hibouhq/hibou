package versioncmp

import (
	"strings"
	"unicode"
)

// RPM compares epoch:version-release values using rpmvercmp semantics.
type RPM struct{}

type rpmVersion struct {
	epoch   int
	version string
	release string
}

func (r *RPM) Compare(a, b string) int {
	av := parseRPMVersion(StripArch(a))
	bv := parseRPMVersion(StripArch(b))

	if cmp := cmpInts(av.epoch, bv.epoch); cmp != 0 {
		return cmp
	}
	if cmp := rpmvercmp(av.version, bv.version); cmp != 0 {
		return cmp
	}
	return rpmvercmp(av.release, bv.release)
}

func (r *RPM) Valid(v string) bool {
	v = strings.TrimSpace(StripArch(v))
	return v != ""
}

func parseRPMVersion(v string) rpmVersion {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "_", "-")
	parsed := rpmVersion{}

	if idx := strings.IndexByte(v, ':'); idx >= 0 {
		parsed.epoch = parseIntDefault(v[:idx])
		v = v[idx+1:]
	}
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		parsed.version = v[:idx]
		parsed.release = v[idx+1:]
	} else {
		parsed.version = v
	}
	return parsed
}

func rpmvercmp(a, b string) int {
	ai, bi := 0, 0
	for {
		ai = rpmSkipSeparators(a, ai)
		bi = rpmSkipSeparators(b, bi)

		if cmp, nextA, nextB, handled := rpmCompareTilde(a, b, ai, bi); handled {
			if cmp != 0 {
				return cmp
			}
			ai = nextA
			bi = nextB
			continue
		}

		if cmp, done := rpmCompareRemainder(a, b, ai, bi); done {
			return cmp
		}

		cmp, nextA, nextB := rpmCompareSegmentPair(a, b, ai, bi)
		if cmp != 0 {
			return cmp
		}

		ai = nextA
		bi = nextB
	}
}

func rpmCompareTilde(a, b string, ai, bi int) (int, int, int, bool) {
	hasATilde := ai < len(a) && a[ai] == '~'
	hasBTilde := bi < len(b) && b[bi] == '~'
	if !hasATilde && !hasBTilde {
		return 0, ai, bi, false
	}
	switch {
	case hasATilde && hasBTilde:
		return 0, ai + 1, bi + 1, true
	case hasATilde:
		return -1, ai, bi, true
	default:
		return 1, ai, bi, true
	}
}

func rpmCompareRemainder(a, b string, ai, bi int) (int, bool) {
	if ai >= len(a) && bi >= len(b) {
		return 0, true
	}
	if ai >= len(a) {
		if rpmOnlyZeroRemainder(b, bi) {
			return 0, true
		}
		return -1, true
	}
	if bi >= len(b) {
		if rpmOnlyZeroRemainder(a, ai) {
			return 0, true
		}
		return 1, true
	}
	return 0, false
}

func rpmCompareSegmentPair(a, b string, ai, bi int) (int, int, int) {
	aNum := unicode.IsDigit(rune(a[ai]))
	bNum := unicode.IsDigit(rune(b[bi]))
	switch {
	case aNum && !bNum:
		return 1, ai, bi
	case !aNum && bNum:
		return -1, ai, bi
	}
	aSeg, nextA := rpmReadSegment(a, ai, aNum)
	bSeg, nextB := rpmReadSegment(b, bi, bNum)
	if aNum {
		return rpmCompareNumeric(aSeg, bSeg), nextA, nextB
	}
	return cmpStrings(aSeg, bSeg), nextA, nextB
}

func rpmOnlyZeroRemainder(s string, idx int) bool {
	for {
		idx = rpmSkipSeparators(s, idx)
		if idx >= len(s) {
			return true
		}
		if !unicode.IsDigit(rune(s[idx])) {
			return false
		}
		seg, next := rpmReadSegment(s, idx, true)
		if trimLeadingZeros(seg) != "0" {
			return false
		}
		idx = next
	}
}

func rpmSkipSeparators(s string, idx int) int {
	for idx < len(s) {
		r := rune(s[idx])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || s[idx] == '~' {
			break
		}
		idx++
	}
	return idx
}

func rpmReadSegment(s string, idx int, numeric bool) (string, int) {
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

func rpmCompareNumeric(a, b string) int {
	a = trimLeadingZeros(a)
	b = trimLeadingZeros(b)
	if cmp := cmpInts(len(a), len(b)); cmp != 0 {
		return cmp
	}
	return cmpStrings(a, b)
}
