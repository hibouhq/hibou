package versioncmp

import (
	"regexp"
	"strings"
)

// PyPI compares PEP 440 versions.
type PyPI struct{}

type pypiVersion struct {
	epoch   int
	release []int
	dev     int
	pre     int
	post    int
	local   string
	valid   bool
}

var (
	pypiReleaseRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)
	pypiPreRe     = regexp.MustCompile(`^(?:[-_\.]?)(alpha|beta|rc|c|a|b)(\d*)`)
	pypiPostRe    = regexp.MustCompile(`^(?:[-_\.]?)(post)(\d*)`)
	pypiDevRe     = regexp.MustCompile(`^(?:[-_\.]?)(dev)(\d*)`)
)

const (
	pypiMainPhaseDev  = -1
	pypiMainPhaseA    = 0
	pypiMainPhaseB    = 1
	pypiMainPhaseRC   = 2
	pypiMainPhaseRel  = 3
	pypiMainPhasePost = 4
	pypiPreStride     = 1_000_000
)

func (p *PyPI) Compare(a, b string) int {
	av := parsePyPIVersion(a)
	bv := parsePyPIVersion(b)

	if cmp := cmpInts(av.epoch, bv.epoch); cmp != 0 {
		return cmp
	}
	if cmp := compareIntSlices(av.release, bv.release); cmp != 0 {
		return cmp
	}
	return comparePyPIPhases(av, bv)
}

func (p *PyPI) Valid(v string) bool {
	return parsePyPIVersion(v).valid
}

func parsePyPIVersion(v string) pypiVersion {
	v = strings.ToLower(strings.TrimSpace(v))
	parsed := pypiVersion{dev: -1, pre: -1, post: -1}
	if idx := strings.IndexByte(v, '+'); idx >= 0 {
		parsed.local = v[idx+1:]
		v = v[:idx]
	}
	if idx := strings.IndexByte(v, '!'); idx >= 0 {
		parsed.epoch = parseIntDefault(v[:idx], 0)
		v = v[idx+1:]
	}
	m := pypiReleaseRe.FindStringSubmatch(v)
	if m == nil {
		return pypiVersion{}
	}
	for _, part := range strings.Split(m[1], ".") {
		parsed.release = append(parsed.release, parseIntDefault(part, 0))
	}
	parsed.release = trimTrailingZeroInts(parsed.release)
	parsed.valid = true
	remaining := v[len(m[1]):]
	for remaining != "" {
		if match := pypiPreRe.FindStringSubmatch(remaining); match != nil {
			if parsed.pre >= 0 {
				parsed.valid = false
				return parsed
			}
			parsed.pre = encodePyPIPre(normalizePyPIStage(match[1]), parseIntDefault(match[2], 0))
			remaining = remaining[len(match[0]):]
			continue
		}
		if match := pypiPostRe.FindStringSubmatch(remaining); match != nil {
			if parsed.post >= 0 {
				parsed.valid = false
				return parsed
			}
			parsed.post = parseIntDefault(match[2], 0)
			remaining = remaining[len(match[0]):]
			continue
		}
		if match := pypiDevRe.FindStringSubmatch(remaining); match != nil {
			if parsed.dev >= 0 {
				parsed.valid = false
				return parsed
			}
			parsed.dev = parseIntDefault(match[2], 0)
			remaining = remaining[len(match[0]):]
			continue
		}
		parsed.valid = false
		return parsed
	}
	return parsed
}

func comparePyPIPhases(a, b pypiVersion) int {
	aPhase := pypiMainPhase(a)
	bPhase := pypiMainPhase(b)
	if cmp := cmpInts(aPhase, bPhase); cmp != 0 {
		return cmp
	}

	switch aPhase {
	case pypiMainPhaseDev:
		return cmpInts(a.dev, b.dev)
	case pypiMainPhaseA, pypiMainPhaseB, pypiMainPhaseRC:
		if cmp := cmpInts(a.pre, b.pre); cmp != 0 {
			return cmp
		}
		return compareOptionalDev(a.dev, b.dev)
	case pypiMainPhasePost:
		if cmp := cmpInts(a.post, b.post); cmp != 0 {
			return cmp
		}
		return compareOptionalDev(a.dev, b.dev)
	default:
		return 0
	}
}

func pypiMainPhase(v pypiVersion) int {
	if v.post >= 0 {
		return pypiMainPhasePost
	}
	if v.pre >= 0 {
		return v.pre / pypiPreStride
	}
	if v.dev >= 0 {
		return pypiMainPhaseDev
	}
	return pypiMainPhaseRel
}

func compareOptionalDev(a, b int) int {
	switch {
	case a < 0 && b < 0:
		return 0
	case a < 0:
		return 1
	case b < 0:
		return -1
	default:
		return cmpInts(a, b)
	}
}

func encodePyPIPre(stage string, number int) int {
	return pypiPreRank(stage)*pypiPreStride + number
}

func pypiPreRank(stage string) int {
	switch stage {
	case "a":
		return pypiMainPhaseA
	case "b":
		return pypiMainPhaseB
	default:
		return pypiMainPhaseRC
	}
}

func normalizePyPIStage(stage string) string {
	switch stage {
	case "alpha":
		return "a"
	case "beta":
		return "b"
	case "c":
		return "rc"
	default:
		return stage
	}
}

func compareIntSlices(a, b []int) int {
	max := len(a)
	if len(b) > max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if cmp := cmpInts(av, bv); cmp != 0 {
			return cmp
		}
	}
	return 0
}
