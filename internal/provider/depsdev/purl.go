// Package depsdev reads package signals from the deps.dev API (ADR-048):
// release cooldown, registry deprecation, low usage and recommended
// versions. It is an enrichment of the dependency inventory, never a
// vulnerability source: malicious and vulnerable findings come from the
// advisory providers, and this package only records what deps.dev says so
// a disagreement can be measured.
//
// deps.dev is a live, per-version API with no bulk export, so unlike the
// KEV and EPSS mirrors it cannot be mirrored for an offline instance. The
// sync therefore stores what it looked up, with a fetched_at, and the UI
// says "not evaluated" for anything it has not seen.
package depsdev

import (
	"net/url"
	"strings"
)

// VersionKey is deps.dev's identity for a package version.
type VersionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Systems deps.dev serves (docs.deps.dev, 2026-10). Everything else, OS
// packages and IaC included, is out of scope for this provider.
const (
	SystemNPM      = "NPM"
	SystemPyPI     = "PYPI"
	SystemMaven    = "MAVEN"
	SystemGo       = "GO"
	SystemCargo    = "CARGO"
	SystemNuGet    = "NUGET"
	SystemRubyGems = "RUBYGEMS"
)

// purlTypeToSystem maps a purl type to a deps.dev system. Only the seven
// supported systems appear; a missing type means "not covered", not an
// error.
var purlTypeToSystem = map[string]string{
	"npm":    SystemNPM,
	"pypi":   SystemPyPI,
	"maven":  SystemMaven,
	"golang": SystemGo,
	"gomod":  SystemGo,
	"cargo":  SystemCargo,
	"nuget":  SystemNuGet,
	"gem":    SystemRubyGems,
	"gems":   SystemRubyGems,
}

// ParsePurl turns a package URL into a deps.dev version key and the
// canonical purl deps.dev accepts (type, namespace, name and version only:
// qualifiers and subpaths make its purl endpoints fail). ok is false for a
// purl of an unsupported type, without a version, or malformed.
//
// Name conventions follow deps.dev: Maven is "group:artifact", npm keeps
// the "@scope/name" form, Go is the full module path, PyPI and NuGet are
// lower-cased because deps.dev normalises them that way.
func ParsePurl(purl string) (key VersionKey, canonical string, ok bool) {
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, "pkg:") {
		return VersionKey{}, "", false
	}
	remainder := strings.TrimPrefix(trimmed, "pkg:")
	if idx := strings.IndexAny(remainder, "#?"); idx >= 0 {
		remainder = remainder[:idx]
	}
	// A literal '@' only appears before the version: namespace and name
	// segments percent-encode theirs ("%40scope").
	version := ""
	if idx := strings.LastIndex(remainder, "@"); idx >= 0 {
		version = remainder[idx+1:]
		remainder = remainder[:idx]
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return VersionKey{}, "", false
	}
	segments := strings.Split(remainder, "/")
	if len(segments) < 2 {
		return VersionKey{}, "", false
	}
	purlType := strings.ToLower(strings.TrimSpace(segments[0]))
	system, supported := purlTypeToSystem[purlType]
	if !supported {
		return VersionKey{}, "", false
	}
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
		return VersionKey{}, "", false
	}
	var name string
	switch system {
	case SystemMaven:
		if len(parts) < 2 {
			return VersionKey{}, "", false
		}
		name = strings.Join(parts[:len(parts)-1], ".") + ":" + parts[len(parts)-1]
	case SystemNPM, SystemGo:
		name = strings.Join(parts, "/")
		if system == SystemGo && (name == "stdlib" || name == "toolchain") {
			// OSV's names for the Go standard library and toolchain; deps.dev
			// has no such packages and would answer NOT_FOUND.
			return VersionKey{}, "", false
		}
	case SystemPyPI:
		name = normalizePyPIName(parts[len(parts)-1])
		parts[len(parts)-1] = name
	case SystemNuGet:
		name = strings.ToLower(parts[len(parts)-1])
	default:
		name = parts[len(parts)-1]
	}
	canonicalType := purlType
	switch purlType {
	case "gomod":
		canonicalType = "golang"
	case "gems":
		canonicalType = "gem"
	}
	encoded := make([]string, 0, len(parts))
	for _, part := range parts {
		encoded = append(encoded, url.PathEscape(part))
	}
	canonical = "pkg:" + canonicalType + "/" + strings.Join(encoded, "/") + "@" + url.PathEscape(version)
	return VersionKey{System: system, Name: name, Version: version}, canonical, true
}

// normalizePyPIName applies PEP 503: lower case, and any run of '-', '_' or
// '.' becomes one '-'. deps.dev keys PyPI packages by that form.
func normalizePyPIName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	pendingDash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			pendingDash = true
			continue
		}
		if pendingDash && b.Len() > 0 {
			b.WriteByte('-')
		}
		pendingDash = false
		b.WriteRune(r)
	}
	return b.String()
}

// PackageIdentity is the purl without its version, used for private
// namespace matching ("pkg:npm/@acme/*").
func PackageIdentity(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if idx := strings.IndexAny(trimmed, "#?"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if idx := strings.LastIndex(trimmed, "@"); idx > strings.Index(trimmed, "/") {
		trimmed = trimmed[:idx]
	}
	if decoded, err := url.PathUnescape(trimmed); err == nil {
		trimmed = decoded
	}
	return trimmed
}

// MatchesNamespace reports whether the purl (version stripped, decoded)
// matches a pattern such as "pkg:npm/@acme/*", "pkg:maven/com.acme.*" or an
// exact identity. '*' matches any run of characters including '/', which is
// what a namespace rule means; there is no other metacharacter.
func MatchesNamespace(purl, pattern string) bool {
	identity := PackageIdentity(purl)
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(identity, pattern)
	}
	pieces := strings.Split(strings.ToLower(pattern), "*")
	subject := strings.ToLower(identity)
	if !strings.HasPrefix(subject, pieces[0]) {
		return false
	}
	subject = subject[len(pieces[0]):]
	for i := 1; i < len(pieces); i++ {
		piece := pieces[i]
		if piece == "" {
			if i == len(pieces)-1 {
				return true
			}
			continue
		}
		idx := strings.Index(subject, piece)
		if idx < 0 {
			return false
		}
		if i == len(pieces)-1 && !strings.HasSuffix(subject, piece) {
			return false
		}
		subject = subject[idx+len(piece):]
	}
	return subject == "" || strings.HasSuffix(pattern, "*")
}

// IsPrivate reports whether any pattern matches the purl.
func IsPrivate(purl string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchesNamespace(purl, pattern) {
			return true
		}
	}
	return false
}

// WithVersion returns the purl of the same package at another version:
// the remediation versions an advisory names, looked up with the same
// policy as the affected one.
func WithVersion(purl, version string) string {
	trimmed := strings.TrimSpace(purl)
	if idx := strings.IndexAny(trimmed, "#?"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if idx := strings.LastIndex(trimmed, "@"); idx > strings.Index(trimmed, "/") {
		trimmed = trimmed[:idx]
	}
	return trimmed + "@" + url.PathEscape(strings.TrimSpace(version))
}
