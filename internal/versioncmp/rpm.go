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
			if rpmOnlyZeroRemainder(b, bi) {
				return 0
			}
			return -1
		}
		if bi >= len(b) {
			if rpmOnlyZeroRemainder(a, ai) {
				return 0
			}
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

		aSeg, nextA := rpmReadSegment(a, ai, aNum)
		bSeg, nextB := rpmReadSegment(b, bi, bNum)

		var cmp int
		if aNum {
			cmp = rpmCompareNumeric(aSeg, bSeg)
		} else {
			cmp = cmpStrings(aSeg, bSeg)
		}
		if cmp != 0 {
			return cmp
		}

		ai = nextA
		bi = nextB
	}
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
