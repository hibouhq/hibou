// Package scanbundle prepares and imports offline scanner bundles (ADR-035
// "Offline distribution"): a connected machine exports the catalog's
// artifacts for chosen platforms with a manifest; an air-gapped installation
// imports and verifies them into the read-only directory its
// scanner_distribution.bundle_dir points at. A bundle never changes what is
// pinned: every artifact must match the catalog's sha256.
package scanbundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanrun"
)

// ManifestName is the manifest file at the bundle root.
const ManifestName = "hibou-scanner-bundle.json"

// Manifest describes a bundle.
type Manifest struct {
	SchemaVersion   int        `json:"schema_version"`
	CatalogRevision string     `json:"catalog_revision"`
	CreatedAt       time.Time  `json:"created_at"`
	Platforms       []string   `json:"platforms"`
	Artifacts       []Artifact `json:"artifacts"`
	// Missing names what was asked for and is not in the bundle (a scanner
	// without a build for a requested platform): an import says so instead
	// of pretending the platform is covered.
	Missing []string `json:"missing,omitempty"`
}

// Artifact is one file of the bundle, at the path offline Resolve expects:
// <scanner-id>/<engine-version>/<asset or Maven path>.
type Artifact struct {
	ScannerID string `json:"scanner_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	SourceURL string `json:"source_url"`
	License   string `json:"license"`
}

// ExportOptions selects what to export.
type ExportOptions struct {
	OutDir string
	// Scanners limits the export; empty means every catalog scanner.
	Scanners []string
	// Platforms are os/arch pairs ("linux/amd64"); Maven artifacts are
	// platform-independent and always included.
	Platforms []string
	Fetcher   *scanrun.Fetcher
}

// Export downloads, verifies and lays out the artifacts, then writes the
// manifest. Downloads go through the fetcher: sha256 checked before a file
// enters the bundle.
func Export(ctx context.Context, catalog *scancatalog.Catalog, opts ExportOptions) (*Manifest, error) {
	if len(opts.Platforms) == 0 {
		return nil, errors.New("name at least one platform (os/arch): a binary for another platform is not usable coverage")
	}
	wanted := map[string]bool{}
	for _, id := range opts.Scanners {
		if _, ok := catalog.Scanner(id); !ok {
			return nil, fmt.Errorf("unknown scanner %q", id)
		}
		wanted[id] = true
	}
	manifest := &Manifest{SchemaVersion: 1, CatalogRevision: catalog.Revision, CreatedAt: time.Now().UTC(), Platforms: opts.Platforms}
	for i := range catalog.Scanners {
		scanner := &catalog.Scanners[i]
		if len(wanted) > 0 && !wanted[scanner.ID] {
			continue
		}
		distributions := make([]*scancatalog.Distribution, 0)
		for j := range scanner.Distributions {
			if scanner.Distributions[j].Kind == scancatalog.KindMaven {
				distributions = append(distributions, &scanner.Distributions[j])
			}
		}
		for _, platform := range opts.Platforms {
			goos, goarch, ok := strings.Cut(platform, "/")
			if !ok {
				return nil, fmt.Errorf("platform %q: want os/arch", platform)
			}
			hasBinaries := false
			for j := range scanner.Distributions {
				if scanner.Distributions[j].Kind == scancatalog.KindBinary {
					hasBinaries = true
				}
			}
			if !hasBinaries {
				continue
			}
			binary, ok := scanner.BinaryFor(goos, goarch, "")
			if !ok {
				manifest.Missing = append(manifest.Missing, scanner.ID+" "+platform)
				continue
			}
			distributions = append(distributions, binary)
		}
		for _, distribution := range distributions {
			location, err := scancatalog.DistributionConfig{}.Resolve(scanner, distribution)
			if err != nil {
				return nil, err
			}
			relative := bundlePath(scanner, distribution)
			cached, err := opts.Fetcher.Fetch(ctx, location, filepath.Base(relative), distribution.Kind == scancatalog.KindBinary)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", scanner.ID, err)
			}
			destination := filepath.Join(opts.OutDir, filepath.FromSlash(relative))
			size, err := copyInto(cached, destination)
			if err != nil {
				return nil, err
			}
			manifest.Artifacts = append(manifest.Artifacts, Artifact{
				ScannerID: scanner.ID, Path: relative, SHA256: distribution.SHA256, Size: size,
				SourceURL: distribution.URL, License: scanner.License,
			})
		}
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].Path < manifest.Artifacts[j].Path })
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	// #nosec G306 -- public metadata, read by whoever imports the bundle
	if err := os.WriteFile(filepath.Join(opts.OutDir, ManifestName), append(encoded, '\n'), 0o640); err != nil {
		return nil, err
	}
	return manifest, nil
}

// Import verifies a bundle against the catalog and copies it into the store
// directory, read-only. Nothing is copied unless everything verifies: a
// corrupt or foreign artifact fails the whole import.
//
// Each artifact is hashed while it is copied into a staging directory inside
// the store, and only the staged copies are renamed into place: what was
// verified is exactly what lands in the store (no verify-then-reopen race).
// Symbolic links anywhere under the bundle are refused.
func Import(catalog *scancatalog.Catalog, bundleDir, storeDir string) (*Manifest, error) {
	manifestFile, err := openRegular(bundleDir, ManifestName)
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(manifestFile, 16<<20))
	_ = manifestFile.Close()
	if err != nil {
		return nil, fmt.Errorf("read bundle manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode bundle manifest: %w", err)
	}
	pinned := map[string]string{}
	for i := range catalog.Scanners {
		scanner := &catalog.Scanners[i]
		for j := range scanner.Distributions {
			pinned[bundlePath(scanner, &scanner.Distributions[j])] = scanner.Distributions[j].SHA256
		}
	}
	for _, artifact := range manifest.Artifacts {
		if strings.Contains(artifact.Path, "..") || filepath.IsAbs(artifact.Path) || strings.HasPrefix(artifact.Path, "/") {
			return nil, fmt.Errorf("artifact path %q escapes the bundle", artifact.Path)
		}
		expected, ok := pinned[artifact.Path]
		if !ok {
			return nil, fmt.Errorf("%s is not an artifact of catalog %s", artifact.Path, catalog.Revision)
		}
		if expected != artifact.SHA256 {
			return nil, fmt.Errorf("%s: manifest sha256 differs from the catalog", artifact.Path)
		}
	}

	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(storeDir, ".import-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	staged := make([]string, len(manifest.Artifacts))
	for i, artifact := range manifest.Artifacts {
		staged[i] = filepath.Join(staging, strconv.Itoa(i))
		if err := stageVerified(bundleDir, artifact.Path, staged[i], pinned[artifact.Path]); err != nil {
			return nil, err
		}
	}
	for i, artifact := range manifest.Artifacts {
		mode := os.FileMode(0o440)
		if strings.Count(artifact.Path, "/") == 2 && !strings.HasSuffix(artifact.Path, ".jar") {
			mode = 0o550 // a binary
		}
		if err := os.Chmod(staged[i], mode); err != nil {
			return nil, err
		}
		destination := filepath.Join(storeDir, filepath.FromSlash(artifact.Path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			return nil, err
		}
		if err := noSymlinkBelow(storeDir, filepath.Dir(destination)); err != nil {
			return nil, err
		}
		// #nosec G703 -- destination is storeDir joined with a catalog-pinned bundle path
		if err := os.Rename(staged[i], destination); err != nil {
			return nil, err
		}
	}
	// #nosec G306 G703 -- read-only public metadata for the server user; storeDir is the operator's --into
	if err := os.WriteFile(filepath.Join(storeDir, ManifestName), data, 0o440); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// stageVerified copies one bundle artifact to staged while hashing it, and
// fails unless the bytes written are the pinned ones.
func stageVerified(bundleDir, relative, staged, expected string) error {
	in, err := openRegular(bundleDir, relative)
	if err != nil {
		return fmt.Errorf("%s: %w", relative, err)
	}
	defer in.Close()
	out, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- staging file in the store
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, hash), in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("%s: %w", relative, err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("%w: %s", scanrun.ErrDigestMismatch, relative)
	}
	return nil
}

// errSymlink: a bundle must be plain files and directories; a link could
// point the import at anything on the importing machine.
var errSymlink = errors.New("symbolic links are not allowed in a scanner bundle")

// openRegular opens root/relative, refusing a symbolic link in any path
// component and anything but a regular file. The opened file is checked to
// be the one inspected (a swap between Lstat and Open is detected).
func openRegular(root, relative string) (*os.File, error) {
	full := filepath.Join(root, filepath.FromSlash(relative))
	if err := noSymlinkBelow(root, full); err != nil {
		return nil, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", relative)
	}
	file, err := os.Open(full) // #nosec G304 -- inside the operator's bundle, no symlink component
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed while being imported", relative)
	}
	return file, nil
}

// noSymlinkBelow checks every path component from root (exclusive) down to
// target (inclusive) with Lstat.
func noSymlinkBelow(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside %s", target, root)
	}
	if relative == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", errSymlink, current)
		}
	}
	return nil
}

// bundlePath mirrors scancatalog's offline layout.
func bundlePath(scanner *scancatalog.Scanner, distribution *scancatalog.Distribution) string {
	location, err := scancatalog.DistributionConfig{Mode: scancatalog.ModeOffline, BundleDir: "/"}.Resolve(scanner, distribution)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(location.URL, "file:///")
}

func copyInto(source, destination string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return 0, err
	}
	in, err := os.Open(source) // #nosec G304 -- verified artifact path
	if err != nil {
		return 0, err
	}
	defer in.Close()
	_ = os.Remove(destination)                                                      // a previous read-only copy
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- bundle layout path
	if err != nil {
		return 0, err
	}
	size, err := io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return size, err
}

// ReadManifest reads the manifest Import wrote into a store directory.
func ReadManifest(storeDir string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(storeDir, ManifestName)) // #nosec G304 -- the operator's configured bundle_dir
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode bundle manifest: %w", err)
	}
	return &manifest, nil
}
