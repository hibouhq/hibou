package lsp

import (
	"context"
	"os"
	"path/filepath"
	"sort"
)

// Diagnostics for files that are not open. Editors list published
// diagnostics in their problems panel, so publishing only open documents
// would hide every finding in a file the user has not opened. Closed files
// are read from disk and mapped like open ones.

// maxDiskFiles bounds how many closed files one refresh publishes.
const maxDiskFiles = 2000

// maxDiskFileBytes skips files too large to diff cheaply.
const maxDiskFileBytes = 4 << 20

// publishClosedFiles publishes the findings of every file with findings that
// is not open, and clears files that no longer have any. It only runs when
// the snapshot or HEAD changed since the last run, unless force is set.
func (s *Server) publishClosedFiles(ctx context.Context, w *workspace, force bool) {
	w.mu.Lock()
	key := w.lastHead
	if w.snapshot != nil && w.state == stateReady {
		// The digest changes when triage changes a finding without a new
		// snapshot (marked false positive in the web UI).
		key = w.snapshot.ID + "@" + w.lastHead + "#" + w.digest
	}
	if !force && key == w.diskKey {
		w.mu.Unlock()
		return
	}
	var rels []string
	if w.state == stateReady {
		for rel := range w.byPath {
			rels = append(rels, rel)
		}
	}
	prev := w.diskURIs
	w.mu.Unlock()
	sort.Strings(rels)
	if len(rels) > maxDiskFiles {
		rels = rels[:maxDiskFiles]
	}

	open := map[string]bool{}
	for _, d := range s.docsOf(w) {
		open[d.uri] = true
	}
	published := map[string]bool{}
	for _, rel := range rels {
		if ctx.Err() != nil {
			return
		}
		uri := pathToURI(filepath.Join(w.root, filepath.FromSlash(rel)))
		if open[uri] {
			continue // the open buffer is published by publish()
		}
		if s.publishDiskFile(ctx, w, rel, uri) {
			published[uri] = true
		}
	}
	for uri := range prev {
		if !published[uri] && !open[uri] {
			_ = s.conn.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{URI: uri, Diagnostics: []diagnostic{}})
		}
	}

	w.mu.Lock()
	w.diskKey, w.diskURIs = key, published
	w.mu.Unlock()
}

// publishDiskFile publishes the diagnostics of one closed file read from
// disk. It returns false when the file is missing locally or too large.
func (s *Server) publishDiskFile(ctx context.Context, w *workspace, rel, uri string) bool {
	path := filepath.Join(w.root, filepath.FromSlash(rel))
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDiskFileBytes {
		return false
	}
	data, err := os.ReadFile(path) // #nosec G304 -- a file inside the user's own work tree; normalizeRepoPath keeps rel under the root.
	if err != nil {
		return false
	}
	d := document{uri: uri, path: path, ws: w, rel: rel}
	d.setText(string(data))
	s.publishSnapshot(ctx, d, nil)
	return true
}
