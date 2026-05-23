// Package ui embeds the built Vue SPA for inclusion in the hibou binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist/*
var embedded embed.FS

// FS returns the embedded SPA filesystem rooted at dist/, or nil if
// the dist directory is empty (e.g. during development without a frontend build).
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil
	}

	// Check if the directory has any entries.
	entries, err := fs.ReadDir(sub, ".")
	if err != nil || len(entries) == 0 {
		return nil
	}

	return sub
}
