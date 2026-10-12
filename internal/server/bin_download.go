package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/version"
)

var (
	binOSes   = []string{"linux", "darwin", "windows"}
	binArches = []string{"amd64", "arm64"}
)

// handleBinVersion reports the CLI version the server serves and the sha256
// of each served binary, keyed "os/arch". The checksums let the action
// detect a truncated or altered download; they come from the same server,
// so they are no defence against that server itself.
func (s *Server) handleBinVersion(w http.ResponseWriter, r *http.Request) {
	checksums := map[string]string{}
	if dir, err := binDir(); err == nil {
		for _, osName := range binOSes {
			for _, arch := range binArches {
				if sum, ok := binChecksum(filepath.Join(dir, binFilename(osName, arch))); ok {
					checksums[osName+"/"+arch] = sum
				}
			}
		}
	}
	api.JSON(w, http.StatusOK, map[string]any{
		"version": version.Version,
		"commit":  version.Commit,
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"sha256":  checksums,
	})
}

// binChecksums caches each binary's sha256 by path, size and mtime, so the
// files are hashed once, not per CI run.
var binChecksums = struct {
	sync.Mutex
	entries map[string]binChecksumEntry
}{entries: map[string]binChecksumEntry{}}

type binChecksumEntry struct {
	size    int64
	modTime time.Time
	sum     string
}

func binChecksum(path string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	binChecksums.Lock()
	defer binChecksums.Unlock()
	if entry, ok := binChecksums.entries[path]; ok && entry.size == info.Size() && entry.modTime.Equal(info.ModTime()) {
		return entry.sum, true
	}
	file, err := os.Open(path) // #nosec G304 -- path is binDir() joined with a name built from fixed os/arch lists
	if err != nil {
		return "", false
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", false
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	binChecksums.entries[path] = binChecksumEntry{size: info.Size(), modTime: info.ModTime(), sum: sum}
	return sum, true
}

func binFilename(osName, arch string) string {
	ext := ""
	if osName == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("hibou-%s-%s%s", osName, arch, ext)
}

// binDir is the directory of the resolved server executable; the CLI
// binaries live next to it.
func binDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	return filepath.Dir(exePath), nil
}

// handleVersion reports the running version alongside the latest released
// version and whether an update is available. The comparison is served from
// the background update checker's cache, so this never blocks on the network.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if s.updateChecker == nil {
		api.JSON(w, http.StatusOK, map[string]any{
			"current":          version.Version,
			"update_available": false,
		})
		return
	}
	api.JSON(w, http.StatusOK, s.updateChecker.Result())
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

	filename := binFilename(reqOS, reqArch)
	exeDir, err := binDir()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "cannot locate server binary")
		return
	}

	// All binaries live next to the resolved executable
	binPath := filepath.Join(exeDir, filename)
	if sum, ok := binChecksum(binPath); ok {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
		w.Header().Set("X-Hibou-Version", version.Version)
		w.Header().Set("X-Hibou-SHA256", sum)
		http.ServeFile(w, r, binPath)
		return
	}

	api.JSONError(w, http.StatusNotFound, fmt.Sprintf("binary not available for %s/%s", reqOS, reqArch))
}
