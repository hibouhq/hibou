package sbom

import (
	"net/url"
	"strings"
)

// purlNamespaceJoin lists purl types whose namespace is part of the package
// name advisory databases key on (OSV, GHSA): a scoped npm package is
// "@scope/name", a Go module is its full path, a Maven artifact is
// "group:artifact". OS-package types (deb, apk, rpm, …) are absent on
// purpose — their namespace is the distro vendor, never part of the advisory
// name.
var purlNamespaceJoin = map[string]string{
	"npm":      "/",
	"golang":   "/",
	"gomod":    "/",
	"composer": "/",
	"github":   "/",
	"maven":    ":",
}

// canonicalComponentName resolves the advisory-facing package name for a
// component. CycloneDX (and some SPDX generators) split scoped names into
// group + name; matching advisories on the bare name both fabricates malware
// matches against unscoped typosquat packages and misses real advisories for
// the scoped package. The PURL is authoritative when parseable; group+name is
// the fallback; the bare name is last.
func canonicalComponentName(purl, group, name string) string {
	if fromPURL := packageNameFromPURL(purl); fromPURL != "" {
		return fromPURL
	}
	group = strings.TrimSpace(group)
	name = strings.TrimSpace(name)
	if group != "" && name != "" {
		return group + "/" + name
	}
	return name
}

// packageNameFromPURL extracts the decoded namespace+name from a package URL
// for the ecosystems where the namespace is part of the advisory name; other
// types yield the bare name. Returns "" when the purl cannot be parsed.
func packageNameFromPURL(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, "pkg:") {
		return ""
	}
	remainder := strings.TrimPrefix(trimmed, "pkg:")
	// Strip subpath, qualifiers, then the version. A literal '@' only appears
	// before the version — namespace/name segments percent-encode theirs.
	if idx := strings.IndexAny(remainder, "#?"); idx >= 0 {
		remainder = remainder[:idx]
	}
	if idx := strings.LastIndex(remainder, "@"); idx >= 0 {
		remainder = remainder[:idx]
	}
	segments := strings.Split(remainder, "/")
	if len(segments) < 2 {
		return ""
	}
	purlType := strings.ToLower(strings.TrimSpace(segments[0]))
	separator, namespaceIsPartOfName := purlNamespaceJoin[purlType]

	parts := make([]string, 0, len(segments)-1)
	for _, segment := range segments[1:] {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			decoded = segment
		}
		if decoded = strings.TrimSpace(decoded); decoded != "" {
			parts = append(parts, decoded)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	if !namespaceIsPartOfName {
		return parts[len(parts)-1]
	}
	return strings.Join(parts, separator)
}

// PackageNameFromPURL is the advisory-facing name of a package URL:
// "@scope/name", "group:artifact", a Go module path, else the bare name.
func PackageNameFromPURL(purl string) string {
	return packageNameFromPURL(purl)
}

// EcosystemFromPURL maps a package URL's type to the ecosystem name hibou
// stores ("golang" and "gomod" become "go").
func EcosystemFromPURL(purl string) string {
	return ecosystemFromPURL(purl)
}

// VersionFromPURL returns the decoded version of a package URL, "" when it
// has none.
func VersionFromPURL(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if idx := strings.IndexAny(trimmed, "#?"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	idx := strings.LastIndex(trimmed, "@")
	if idx < 0 || idx < strings.Index(trimmed, "/") {
		return ""
	}
	version, err := url.PathUnescape(trimmed[idx+1:])
	if err != nil {
		version = trimmed[idx+1:]
	}
	return strings.TrimSpace(version)
}
