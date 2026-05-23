package server

import (
	"io/fs"
	"net/http"
	"strings"
)

// spaHandler serves static files from the embedded filesystem and falls back
// to index.html for client-side routing.
func spaHandler(siteFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(siteFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Try to open the file. If it exists, serve it.
		if f, err := siteFS.Open(path); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}

		// Fall back to index.html for SPA client-side routes.
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
