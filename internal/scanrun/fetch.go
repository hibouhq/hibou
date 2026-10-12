// Package scanrun executes a scan plan's jobs in CI (ADR-035 §1, §4): it
// fetches each scanner artifact from the location the plan resolved, verifies
// its sha256 before use, caches it by digest, and runs the scanner through an
// adapter that never goes through a shell.
package scanrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/hibouhq/hibou/internal/scancatalog"
)

// maxArtifactBytes bounds one download (the interfile OpenGrep build is
// ~170 MB).
const maxArtifactBytes = 1 << 30

// ErrDigestMismatch: the artifact is not the one the catalog pinned.
var ErrDigestMismatch = errors.New("artifact sha256 does not match the catalog")

// Fetcher downloads and verifies artifacts into a digest-keyed cache.
type Fetcher struct {
	CacheDir string
	Client   *http.Client
}

// upstreamRedirectHosts are where upstream release URLs legitimately
// redirect (GitHub release assets). Mirrors and approved locations get no
// cross-host redirect at all: a mirror that redirects elsewhere is refused
// (ADR-035 "redirects to unapproved hosts").
var upstreamRedirectHosts = map[string]bool{
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// redirectPolicy allows same-host https redirects, and the GitHub asset CDN
// for upstream locations only.
func redirectPolicy(source string) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if request.URL.Scheme != "https" {
			return fmt.Errorf("redirect to %s refused: not https", request.URL.Scheme)
		}
		origin := via[0].URL.Hostname()
		host := request.URL.Hostname()
		if host == origin || (source == "upstream" && upstreamRedirectHosts[host]) {
			return nil
		}
		return fmt.Errorf("redirect from %s to %s refused: not an approved host", origin, host)
	}
}

// Fetch returns a local path to the verified artifact. A cache hit is
// re-hashed before use (a poisoned cache must not be trusted, ADR-035).
// Only https and file:// (an imported offline bundle) are accepted; the
// location already respects the distribution policy, so there is no
// fallback anywhere here.
func (f *Fetcher) Fetch(ctx context.Context, location scancatalog.Location, name string, executable bool) (string, error) {
	if len(location.SHA256) != 64 {
		return "", fmt.Errorf("artifact %s has no pinned sha256", name)
	}
	dir := filepath.Join(f.CacheDir, location.SHA256)
	target := filepath.Join(dir, filepath.Base(name))
	if digest, err := FileSHA256(target); err == nil && digest == location.SHA256 {
		return target, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	parsed, err := url.Parse(location.URL)
	if err != nil {
		return "", fmt.Errorf("artifact location %q: %w", location.URL, err)
	}
	var source io.ReadCloser
	switch parsed.Scheme {
	case "file":
		file, err := os.Open(filepath.FromSlash(parsed.Path))
		if err != nil {
			return "", fmt.Errorf("offline bundle is missing %s: %w", name, err)
		}
		source = file
	case "https":
		client := &http.Client{Timeout: 10 * time.Minute}
		if f.Client != nil {
			copied := *f.Client
			client = &copied
		}
		client.CheckRedirect = redirectPolicy(location.Source)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.URL, nil)
		if err != nil {
			return "", err
		}
		response, err := client.Do(request)
		if err != nil {
			return "", fmt.Errorf("download %s: %w", name, err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return "", fmt.Errorf("download %s: HTTP %d from %s", name, response.StatusCode, parsed.Host)
		}
		source = response.Body
	default:
		return "", fmt.Errorf("artifact location scheme %q is not allowed (https or file only)", parsed.Scheme)
	}
	defer source.Close()

	temporary, err := os.CreateTemp(dir, ".fetch-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(source, maxArtifactBytes+1))
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	if written > maxArtifactBytes {
		return "", fmt.Errorf("artifact %s exceeds %d bytes", name, maxArtifactBytes)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != location.SHA256 {
		return "", fmt.Errorf("%w: %s is %s, pinned %s", ErrDigestMismatch, name, got, location.SHA256)
	}
	mode := os.FileMode(0o640)
	if executable {
		mode = 0o750
	}
	if err := os.Chmod(temporary.Name(), mode); err != nil {
		return "", err
	}
	if err := os.Rename(temporary.Name(), target); err != nil {
		return "", err
	}
	return target, nil
}

// FileSHA256 hashes a file (hex).
func FileSHA256(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- digest-keyed cache path built by Fetch
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
