//go:build withui

// Package ui embeds the built Vue SPA for inclusion in the hibou binary.
//
// The embed is gated behind the `withui` build tag so the package always
// compiles without a frontend build (dev, tests, lint, `make dev-bin`). Only
// release/image builds — which run `build-frontend` first — pass `-tags withui`
// (wired into GO_BUILD in the Makefile) to embed the real SPA. See embed_stub.go
// for the default no-SPA build.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist/*
var embedded embed.FS

// FS returns the embedded SPA filesystem rooted at dist/, or nil if
// the dist directory is empty (e.g. an incomplete frontend build).
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
