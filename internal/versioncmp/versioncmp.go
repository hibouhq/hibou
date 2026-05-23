package versioncmp

import "strings"

// Comparator compares two version strings for a specific ecosystem.
type Comparator interface {
	// Compare returns -1 if a < b, 0 if a == b, 1 if a > b.
	Compare(a, b string) int
	// Valid reports whether v is a valid version for this ecosystem.
	Valid(v string) bool
}

var registry = map[string]Comparator{}

func init() {
	sv := &Semver{}
	registry["go"] = sv
	registry["npm"] = sv
	registry["cargo"] = sv
	registry["nuget"] = &NuGet{}
	registry["maven"] = &Maven{}
	registry["pypi"] = &PyPI{}
	registry["rubygems"] = &RubyGems{}
	registry["rpm"] = &RPM{}
	registry["deb"] = &Debian{}
	registry["apk"] = &APK{}
}

// Get returns the comparator for the given ecosystem.
func Get(ecosystem string) (Comparator, bool) {
	c, ok := registry[strings.ToLower(ecosystem)]
	return c, ok
}

// InRange reports whether version falls within the affected range defined by
// introduced (inclusive lower bound) and fixed (exclusive upper bound).
// If introduced is empty, the range starts from the earliest version.
// If fixed is empty, lastAffected is used as the inclusive upper bound.
// If both fixed and lastAffected are empty, all versions >= introduced are affected.
func InRange(ecosystem, version, introduced, fixed, lastAffected string) (bool, error) {
	c, ok := Get(ecosystem)
	if !ok {
		return false, &EcosystemError{Ecosystem: ecosystem}
	}

	v := StripArch(version)

	if introduced != "" && c.Compare(v, introduced) < 0 {
		return false, nil
	}

	if fixed != "" {
		if c.Compare(v, fixed) >= 0 {
			return false, nil
		}
		return true, nil
	}

	if lastAffected != "" {
		return c.Compare(v, lastAffected) <= 0, nil
	}

	return true, nil
}

// StripArch removes architecture suffixes from version strings.
// Example: "1.2.3-1.el9.x86_64" -> "1.2.3-1.el9"
func StripArch(version string) string {
	archSuffixes := []string{
		".x86_64", ".aarch64", ".arm64", ".armv7hl", ".armv7l",
		".i686", ".i386", ".noarch", ".ppc64le", ".s390x",
		".src",
	}
	for _, suffix := range archSuffixes {
		if strings.HasSuffix(version, suffix) {
			return strings.TrimSuffix(version, suffix)
		}
	}
	return version
}

// EcosystemError is returned when an unsupported ecosystem is requested.
type EcosystemError struct {
	Ecosystem string
}

func (e *EcosystemError) Error() string {
	return "unsupported ecosystem: " + e.Ecosystem
}
