//go:build !withui

// Package ui embeds the built Vue SPA for inclusion in the hibou binary.
//
// This is the default build: no SPA is embedded, so the package compiles
// without a frontend build. The server runs in API-only mode (serve.go logs
// "no embedded SPA found") — this is what `make dev` uses, with Vite serving
// the SPA separately. Release/image builds pass `-tags withui` (see embed.go)
// to embed the real dist/.
package ui

import "io/fs"

// FS returns nil: no SPA is embedded in this build. The server serves the API
// only; the frontend is expected to be served separately (Vite dev server).
func FS() fs.FS {
	return nil
}
