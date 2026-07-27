// Package distro normalizes the distribution identity of OS packages so that
// advisory ranges and components agree on when a distro advisory applies.
//
// A distro advisory is only valid within one distribution release: Alpine 3.18
// and 3.19 fix the same CVE at different package versions, and Debian releases
// backport fixes under the same upstream version. Matching a range from one
// release against a package from another produces false positives, so every
// comparison here is release-scoped and fails closed when the release is
// unknown.
package distro

import "strings"

// Ecosystems whose advisories are release-scoped.
const (
	EcosystemAPK = "apk"
	EcosystemDEB = "deb"
	EcosystemRPM = "rpm"
)

// IsDistroEcosystem reports whether the internal ecosystem names OS packages.
func IsDistroEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case EcosystemAPK, EcosystemDEB, EcosystemRPM:
		return true
	}
	return false
}

// FromPurl extracts (family, release version) from an OS-package purl.
//
// The family is the purl namespace (pkg:apk/alpine/… → "alpine",
// pkg:rpm/redhat/… → "redhat"), which every distro purl carries. The release
// version is the distro qualifier's value, minus any family prefix — Trivy
// emits "distro=alpine-3.18.4" for some ecosystems and a bare "distro=3.9.6"
// for others, so the namespace is the only reliable family source.
func FromPurl(purl string) (string, string) {
	head, qualifiers, _ := strings.Cut(purl, "?")
	if idx := strings.Index(qualifiers, "#"); idx >= 0 {
		qualifiers = qualifiers[:idx]
	}

	family := purlNamespace(head)
	release := ""
	for _, pair := range strings.Split(qualifiers, "&") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key != "distro" || value == "" {
			continue
		}
		qualifierFamily, version := splitDistro(value)
		release = version
		if family == "" {
			family = qualifierFamily
		}
		break
	}
	return family, release
}

// purlNamespace returns the namespace segment of "pkg:type/namespace/name@ver".
func purlNamespace(head string) string {
	rest := strings.TrimPrefix(strings.TrimSpace(head), "pkg:")
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	segments := strings.Split(rest, "/")
	if len(segments) < 3 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(segments[1]))
}

// splitDistro parses "alpine-3.18.4" / "debian-12" / "redhat-9.4" / "3.18.4".
func splitDistro(value string) (string, string) {
	value = strings.ToLower(strings.TrimSpace(value))
	// Family is the leading non-numeric prefix; the version starts at the first
	// digit-led segment ("rocky-9.3" → rocky + 9.3, "3.18.4" → "" + 3.18.4).
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' && (i == 0 || value[i-1] == '-') {
			family := strings.TrimSuffix(value[:max(i-1, 0)], "-")
			return family, value[i:]
		}
	}
	return value, ""
}

// ReleaseKey reduces a version to the granularity advisories are published at,
// per ecosystem: Alpine fixes land per minor ("3.18"), Debian per major ("12"),
// RPM families per major ("9"). An empty version yields an empty key.
func ReleaseKey(ecosystem, version string) string {
	version = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
	if version == "" {
		return ""
	}
	parts := strings.Split(version, ".")
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case EcosystemAPK:
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
		return parts[0]
	case EcosystemDEB, EcosystemRPM:
		return parts[0]
	default:
		return version
	}
}

// osvDistroEcosystems maps OSV release-qualified ecosystem prefixes to the
// internal ecosystem. Red Hat/SUSE style ecosystems ("Red Hat:rhel_aus:8.2::
// appstream") carry stream qualifiers that do not line up with purl distro
// releases, so they are deliberately absent: no reliable release equality means
// no match, and OSV rpm data stays out rather than guessing.
var osvDistroEcosystems = map[string]string{
	"alpine": EcosystemAPK,
	"debian": EcosystemDEB,
}

// ParseOSVEcosystem splits an OSV ecosystem into (internal ecosystem, release).
// "Alpine:v3.18" → (apk, 3.18); "Debian:12" → (deb, 12); a bare "Alpine" or an
// unmapped distro returns ok=false — a range without a release cannot be
// matched safely (see the package comment).
func ParseOSVEcosystem(ecosystem string) (string, string, bool) {
	name, release, hasRelease := strings.Cut(strings.TrimSpace(ecosystem), ":")
	internal, ok := osvDistroEcosystems[strings.ToLower(strings.TrimSpace(name))]
	if !ok || !hasRelease {
		return "", "", false
	}
	release = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(release)), "v")
	if release == "" {
		return "", "", false
	}
	return internal, release, true
}

// OSVEcosystemFor builds the release-qualified OSV ecosystem to query for a
// component ("apk" + "alpine-3.18.4" → "Alpine:v3.18"). ok=false when the
// component's release is unknown — querying the bare ecosystem would return
// ranges from every release.
func OSVEcosystemFor(ecosystem, distroQualifier string) (string, bool) {
	_, version := splitDistro(distroQualifier)
	release := ReleaseKey(ecosystem, version)
	if release == "" {
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case EcosystemAPK:
		return "Alpine:v" + release, true
	case EcosystemDEB:
		return "Debian:" + release, true
	}
	return "", false
}
