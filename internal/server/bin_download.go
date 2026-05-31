package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/version"
)

func (s *Server) handleBinVersion(w http.ResponseWriter, r *http.Request) {
	api.JSON(w, http.StatusOK, map[string]string{
		"version": version.Version,
		"commit":  version.Commit,
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	})
}

func (s *Server) handleBinDownload(w http.ResponseWriter, r *http.Request) {
	reqOS := chi.URLParam(r, "os")
	reqArch := chi.URLParam(r, "arch")

	validOS := map[string]bool{"linux": true, "darwin": true, "windows": true}
	validArch := map[string]bool{"amd64": true, "arm64": true}
	if !validOS[reqOS] || !validArch[reqArch] {
		api.JSONError(w, http.StatusBadRequest, "unsupported os/arch combination")
		return
	}

	ext := ""
	if reqOS == "windows" {
		ext = ".exe"
	}
	filename := fmt.Sprintf("hibou-%s-%s%s", reqOS, reqArch, ext)

	// Resolve the directory containing the running executable
	exePath, err := os.Executable()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "cannot locate server binary")
		return
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "cannot resolve server binary path")
		return
	}
	exeDir := filepath.Dir(exePath)

	// All binaries live in hibou-bin/ next to the resolved executable
	binPath := filepath.Join(exeDir, filename)
	if info, err := os.Lstat(binPath); err == nil && info.Mode().IsRegular() {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
		w.Header().Set("X-Hibou-Version", version.Version)
		http.ServeFile(w, r, binPath)
		return
	}

	api.JSONError(w, http.StatusNotFound, fmt.Sprintf("binary not available for %s/%s", reqOS, reqArch))
}
