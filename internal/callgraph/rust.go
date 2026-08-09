package callgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// RustCrateUsage is CRATE-level reachability input: which crates of the
// dependency graph the workspace's own source actually names (`use foo`,
// `foo::bar`, `extern crate foo`), versus which are merely present in the
// lockfile. Coarser than a call graph; computed from source, not manifests.
type RustCrateUsage struct {
	// Referenced crates are named somewhere in workspace source.
	Referenced []string `json:"referenced"`
	// Present crates are in the dependency graph but never named.
	Present []string `json:"present"`
}

// ScanRustCrateUsage resolves the crate graph with `cargo metadata` and scans
// the workspace members' sources for crate references.
func ScanRustCrateUsage(ctx context.Context, dir string) (*RustCrateUsage, error) {
	if _, err := exec.LookPath("cargo"); err != nil {
		return nil, errors.New("cargo not found on PATH")
	}

	cmd := exec.CommandContext(ctx, "cargo", "metadata", "--format-version", "1", "--locked")
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cargo metadata: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var metadata struct {
		Packages []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Manifest string `json:"manifest_path"`
		} `json:"packages"`
		WorkspaceMembers []string `json:"workspace_members"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &metadata); err != nil {
		return nil, fmt.Errorf("parse cargo metadata: %w", err)
	}

	members := map[string]struct{}{}
	for _, id := range metadata.WorkspaceMembers {
		members[id] = struct{}{}
	}

	// Source roots of the workspace's own packages; dependencies are the rest.
	sourceRoots := []string{}
	dependencyCrates := map[string]struct{}{}
	for _, pkg := range metadata.Packages {
		if _, ok := members[pkg.ID]; ok {
			sourceRoots = append(sourceRoots, filepath.Dir(pkg.Manifest))
			continue
		}
		dependencyCrates[pkg.Name] = struct{}{}
	}

	referencedIdents, err := scanRustIdentifiers(sourceRoots)
	if err != nil {
		return nil, err
	}

	usage := &RustCrateUsage{}
	for crate := range dependencyCrates {
		// In source, a crate named foo-bar is referenced as foo_bar.
		ident := strings.ReplaceAll(crate, "-", "_")
		if _, ok := referencedIdents[ident]; ok {
			usage.Referenced = append(usage.Referenced, crate)
		} else {
			usage.Present = append(usage.Present, crate)
		}
	}
	sort.Strings(usage.Referenced)
	sort.Strings(usage.Present)
	return usage, nil
}

// crateRefPattern matches the ways source names an external crate:
// `use foo::`, `use foo;`, `extern crate foo`, and path uses `foo::bar`.
var crateRefPattern = regexp.MustCompile(`(?m)(?:^|[^\w:])(?:use\s+|extern\s+crate\s+)?([A-Za-z_][A-Za-z0-9_]*)::`)

var useDeclPattern = regexp.MustCompile(`(?m)^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_]*)\s*;`)

var externCratePattern = regexp.MustCompile(`extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*)`)

func scanRustIdentifiers(roots []string) (map[string]struct{}, error) {
	identifiers := map[string]struct{}{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				// Never scan vendored deps or build output as "our" source.
				if entry.Name() == "target" || entry.Name() == "vendor" || entry.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".rs") {
				return nil
			}
			content, err := os.ReadFile(path) //nolint:gosec // G122: CI-side scan of the caller's own checkout; no trust boundary.
			if err != nil {
				return nil
			}
			for _, pattern := range []*regexp.Regexp{crateRefPattern, useDeclPattern, externCratePattern} {
				for _, match := range pattern.FindAllSubmatch(content, -1) {
					identifiers[string(match[1])] = struct{}{}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return identifiers, nil
}
