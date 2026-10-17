package depinventory

import (
	"path"
	"strings"
)

// Version identifies the extractor for digest reuse (ADR-045 §4.1): the
// engine release plus hibou's own rules. Bump the suffix when the
// relationship or scope rules change, since the inventory is a function
// of both.
const Version = "osv-scalibr-v0.5.3+hibou-1"

// manifestNames are the exact file names the allowlisted extractors read,
// plus the manifests the relationship rules read next to them.
var manifestNames = map[string]struct{}{
	"go.mod": {}, "go.sum": {},
	"package.json": {}, "package-lock.json": {}, "npm-shrinkwrap.json": {}, "pnpm-lock.yaml": {}, "yarn.lock": {}, "bun.lock": {},
	"pyproject.toml": {}, "uv.lock": {}, "poetry.lock": {}, "pdm.lock": {}, "Pipfile": {}, "Pipfile.lock": {}, "pylock.toml": {},
	"Cargo.toml": {}, "Cargo.lock": {},
	"pom.xml": {}, "gradle.lockfile": {}, "verification-metadata.xml": {},
}

// IsManifestPath reports whether a repository path is one the extraction
// reads: a recognised file name, or a pip requirements file, outside the
// directories the walk skips. It is the selector for the sparse checkout,
// so it must accept at least everything the extractors would read.
func IsManifestPath(repoPath string) bool {
	repoPath = strings.TrimPrefix(strings.TrimSpace(repoPath), "./")
	if repoPath == "" {
		return false
	}
	dir, base := path.Split(repoPath)
	for _, segment := range strings.Split(strings.Trim(dir, "/"), "/") {
		if segment != "" && skipDirPattern.MatchString(segment) {
			return false
		}
	}
	if _, ok := manifestNames[base]; ok {
		return true
	}
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}
