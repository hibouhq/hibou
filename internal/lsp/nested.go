package lsp

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Limits of the nested-repository scan at startup: shallow, bounded, and
// never inside dependency or build directories.
const (
	nestedMaxDepth = 3
	nestedMaxRepos = 20
)

var nestedSkipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "dist": true, "build": true, "target": true,
	"tmp": true, ".cache": true, ".venv": true, "venv": true, "__pycache__": true,
	".gradle": true, ".idea": true, ".vscode": true,
}

// nestedRepos returns the git work trees below root (not root itself), at
// most nestedMaxDepth levels down. A ".git" file counts too (worktrees and
// submodules).
func nestedRepos(root string) []string {
	root = filepath.Clean(root)
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if path == root {
			return nil
		}
		name := d.Name()
		if name == ".git" || nestedSkipDirs[name] || (strings.HasPrefix(name, ".") && name != ".github") {
			return filepath.SkipDir
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || strings.Count(rel, string(filepath.Separator))+1 > nestedMaxDepth {
			return filepath.SkipDir
		}
		if _, statErr := os.Stat(filepath.Join(path, ".git")); statErr == nil {
			found = append(found, path)
			if len(found) >= nestedMaxRepos {
				return filepath.SkipAll
			}
			return filepath.SkipDir // its own nested repositories belong to it
		}
		return nil
	})
	return found
}

// trackRepositories starts tracking work trees the client reported and
// refreshes the new ones.
func (s *Server) trackRepositories(ctx context.Context, roots []string) {
	for _, root := range roots {
		if root == "" {
			continue
		}
		path, ok := uriToPath(root)
		if !ok {
			path = filepath.Clean(root)
		}
		if ws := s.workspaceFor(ctx, path); ws != nil && ws.isNew() {
			s.refreshWorkspace(ctx, ws, true)
		}
	}
}
