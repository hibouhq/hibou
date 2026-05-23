package versioncmp

import (
	"strings"
	"unicode"
)

// Semver compares semantic versions for Go, npm, and Cargo ecosystems.
type Semver struct{}

type semverVersion struct {
	major      int
	minor      int
	patch      int
	prerelease []string
	valid      bool
}

func (s *Semver) Compare(a, b string) int {
	av := parseSemver(a)
	bv := parseSemver(b)

	if cmp := cmpInts(av.major, bv.major); cmp != 0 {
		return cmp
	}
	if cmp := cmpInts(av.minor, bv.minor); cmp != 0 {
		return cmp
	}
	if cmp := cmpInts(av.patch, bv.patch); cmp != 0 {
		return cmp
	}
	return compareSemverPrerelease(av.prerelease, bv.prerelease)
}

func (s *Semver) Valid(v string) bool {
	return parseSemver(v).valid
}

func parseSemver(v string) semverVersion {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if plus := strings.IndexByte(v, '+'); plus >= 0 {
		v = v[:plus]
	}

	parts := strings.SplitN(v, "-", 2)
	core := strings.Split(parts[0], ".")
	if len(core) < 2 || len(core) > 3 {
		return semverVersion{}
	}
	if len(core) == 2 {
		core = append(core, "0")
	}
	if !isDigits(core[0]) || !isDigits(core[1]) || !isDigits(core[2]) {
		return semverVersion{}
	}

	parsed := semverVersion{
		major: parseIntDefault(core[0], 0),
		minor: parseIntDefault(core[1], 0),
		patch: parseIntDefault(core[2], 0),
		valid: true,
	}

	if len(parts) == 2 {
		ids := strings.Split(parts[1], ".")
		for _, id := range ids {
			if id == "" || !validSemverIdentifier(id) {
				return semverVersion{}
			}
		}
		parsed.prerelease = ids
	}

	return parsed
}

func validSemverIdentifier(id string) bool {
	for _, r := range id {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			continue
		}
		return false
	}
	return true
}

func compareSemverPrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}

	for i := 0; i < len(a) && i < len(b); i++ {
		aNum := isDigits(a[i])
		bNum := isDigits(b[i])
		switch {
		case aNum && bNum:
			if cmp := cmpInts(parseIntDefault(a[i], 0), parseIntDefault(b[i], 0)); cmp != 0 {
				return cmp
			}
		case aNum && !bNum:
			return -1
		case !aNum && bNum:
			return 1
		default:
			if cmp := cmpStrings(a[i], b[i]); cmp != 0 {
				return cmp
			}
		}
	}

	return cmpInts(len(a), len(b))
}
