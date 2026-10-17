package depinventory

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"

	"github.com/hibouhq/hibou/internal/sbom"
)

// Deliverables (ADR-046 §2, §4.2): what the CLI finds inside a directory,
// a lockfile, an archive, a binary, an SBOM file or a container image.
// Nothing here executes repository content; archives are read with size,
// entry and nesting limits, and every file no extractor recognises is
// listed as not identified, never silently dropped.

// artifactExtractors read what a build produced: jars with their Maven
// metadata (nested ones included), Go and cargo-auditable binaries,
// installed Python packages, installed npm packages, and OS package
// databases of container images.
var artifactExtractors = map[string]extractorConstructor{
	archive.Name:        archive.New,
	gobinary.Name:       gobinary.New,
	cargoauditable.Name: cargoauditable.New,
	wheelegg.Name:       wheelegg.New,
	packagejson.Name:    packagejson.New,
	dpkg.Name:           dpkg.New,
	apk.Name:            apk.New,
	rpm.Name:            rpm.New,
}

// ResolutionArtifact is the highest resolution level: what the deliverable
// contains (ADR-045 §1, T7).
const ResolutionArtifact Resolution = "artifact"

// Unidentified is a file no extractor recognised.
type Unidentified struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Type string `json:"type"`
}

// TargetSummary says what one target yielded.
type TargetSummary struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Components int    `json:"components"`
	Files      int    `json:"files"`
	// SHA256 of a file target, for the release source record.
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Metadata the deliverable carries about itself (ADR-046 §4.3):
	// versions, revisions, labels.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ArtifactInventory is the result of scanning deliverables.
type ArtifactInventory struct {
	Components   []Component    `json:"components"`
	Modules      []Module       `json:"modules"`
	Unidentified []Unidentified `json:"unidentified"`
	// UnidentifiedCount is the full count when the list is capped.
	UnidentifiedCount int             `json:"unidentified_count"`
	Files             int             `json:"files"`
	Targets           []TargetSummary `json:"targets"`
	Notes             []string        `json:"notes,omitempty"`
	Duration          time.Duration   `json:"duration"`
}

// ScanOptions bound a deliverable scan (ADR-046 §7).
type ScanOptions struct {
	Exclude []string
	// MaxArchiveBytes caps the bytes unpacked from one target (default 4 GiB).
	MaxArchiveBytes int64
	// MaxEntries caps the entries unpacked from one target (default 200000).
	MaxEntries int
	// MaxDepth caps nested archives (default 4). Jars nest further inside
	// the Java extractor, which has its own limit.
	MaxDepth int
	Warn     func(string)
	// KeepUnidentified caps the listed unidentified files (default 500).
	KeepUnidentified int
}

func (o ScanOptions) withDefaults() ScanOptions {
	if o.MaxArchiveBytes <= 0 {
		o.MaxArchiveBytes = 4 << 30
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 200000
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 4
	}
	if o.KeepUnidentified <= 0 {
		o.KeepUnidentified = 500
	}
	if o.Warn == nil {
		o.Warn = func(string) {}
	}
	return o
}

// Target kinds.
const (
	KindSource   = "source"
	KindManifest = "manifest"
	KindArchive  = "archive"
	KindBinary   = "binary"
	KindSBOM     = "sbom"
	KindImage    = "image"
)

var archiveExtensions = map[string]bool{
	".zip": true, ".jar": true, ".war": true, ".ear": true, ".aar": true, ".whl": true, ".egg": true, ".nupkg": true,
	".tar": true, ".tgz": true, ".tar.gz": true, ".tar.bz2": false, ".tar.xz": false,
}

// javaArchiveExtensions are read by the Java extractor directly, nested
// jars included; they are never unpacked here.
var javaArchiveExtensions = map[string]bool{".jar": true, ".war": true, ".ear": true, ".aar": true}

// ScanTargets analyses each target and merges the results.
func ScanTargets(ctx context.Context, targets []string, opts ScanOptions) (*ArtifactInventory, error) {
	opts = opts.withDefaults()
	started := time.Now()
	inv := &ArtifactInventory{Components: []Component{}, Unidentified: []Unidentified{}}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	for _, target := range targets {
		if err := scanTarget(ctx, target, opts, inv); err != nil {
			return nil, fmt.Errorf("%s: %w", target, err)
		}
	}
	inv.Components = dedupeComponents(inv.Components)
	sortComponents(inv.Components)
	inv.Modules = buildModules(inv.Components)
	inv.Duration = time.Since(started)
	return inv, nil
}

func scanTarget(ctx context.Context, target string, opts ScanOptions, inv *ArtifactInventory) error {
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return scanDirectory(ctx, target, opts, inv)
	}
	kind := classifyFile(target)
	summary := TargetSummary{Path: target, Kind: kind, Size: info.Size()}
	if digest, err := fileSHA256(target); err == nil {
		summary.SHA256 = digest
	}
	before := len(inv.Components)
	switch kind {
	case KindManifest:
		dir := filepath.Dir(target)
		source, err := Extract(ctx, dir, Options{Exclude: opts.Exclude, Warn: opts.Warn})
		if err != nil {
			return err
		}
		base := filepath.Base(target)
		for _, c := range source.Components {
			if path.Base(c.Path) == base && filepath.Join(dir, filepath.FromSlash(c.Path)) == filepath.Clean(target) {
				c.Path = filepath.ToSlash(target)
				c.Module = moduleOf(c.Path)
				inv.Components = append(inv.Components, c)
			}
		}
		summary.Files = 1
	case KindSBOM:
		data, err := os.ReadFile(target) // #nosec G304 -- a file the user named
		if err != nil {
			return err
		}
		components, err := componentsFromSBOM(data, filepath.ToSlash(target))
		if err != nil {
			return err
		}
		inv.Components = append(inv.Components, components...)
		summary.Files = 1
	case KindArchive, KindBinary:
		root, err := os.MkdirTemp("", "hibou-deps-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(root) }()
		prefix := filepath.ToSlash(target) + "!/"
		var files int
		if kind == KindBinary || javaArchiveExtensions[extensionOf(target)] {
			// The extractor reads it in place: copy the file alone.
			if err := copyFile(target, filepath.Join(root, filepath.Base(target))); err != nil {
				return err
			}
			prefix = filepath.ToSlash(filepath.Dir(target)) + "/"
			files = 1
		} else {
			n, err := unpackArchive(target, root, opts, 0)
			if err != nil {
				return err
			}
			files = n
		}
		components, unidentified, err := extractArtifacts(ctx, root, opts)
		if err != nil {
			return err
		}
		for i := range components {
			components[i].Path = prefix + components[i].Path
			components[i].Module = moduleOf(filepath.ToSlash(target))
		}
		inv.Components = append(inv.Components, components...)
		for i := range unidentified {
			unidentified[i].Path = prefix + unidentified[i].Path
		}
		inv.addUnidentified(unidentified, opts)
		summary.Files = files
		summary.Metadata = deliverableMetadata(target, root)
	default:
		inv.addUnidentified([]Unidentified{{Path: filepath.ToSlash(target), Size: info.Size(), Type: fileType(target)}}, opts)
	}
	summary.Components = len(inv.Components) - before
	inv.Files += summary.Files
	inv.Targets = append(inv.Targets, summary)
	return nil
}

func scanDirectory(ctx context.Context, dir string, opts ScanOptions, inv *ArtifactInventory) error {
	before := len(inv.Components)
	source, err := Extract(ctx, dir, Options{Exclude: opts.Exclude, Warn: opts.Warn})
	if err != nil {
		return err
	}
	inv.Components = append(inv.Components, source.Components...)
	// An unpacked deliverable (site-packages, node_modules, a lib/ full of
	// jars) sits in a directory too: the artifact extractors run as well,
	// and installed packages count as artifact resolution.
	components, _, err := extractArtifacts(ctx, dir, opts)
	if err != nil {
		return err
	}
	inv.Components = append(inv.Components, components...)
	summary := TargetSummary{Path: dir, Kind: KindSource, Components: len(inv.Components) - before}
	inv.Targets = append(inv.Targets, summary)
	return nil
}

// extractArtifacts runs the artifact extractors over a tree and lists what
// nothing recognised.
func extractArtifacts(ctx context.Context, root string, opts ScanOptions) ([]Component, []Unidentified, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	cfg := &cpb.PluginConfig{}
	extractors := make([]filesystem.Extractor, 0, len(artifactExtractors))
	names := make([]string, 0, len(artifactExtractors))
	for name := range artifactExtractors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ext, err := artifactExtractors[name](cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("build extractor %s: %w", name, err)
		}
		if err := plugin.ValidateRequirements(ext, offlineCapabilities); err != nil {
			return nil, nil, fmt.Errorf("extractor %s is not offline-capable: %w", name, err)
		}
		extractors = append(extractors, ext)
	}
	run := &filesystem.Config{
		Extractors:   extractors,
		ScanRoots:    scalibrfs.RealFSScanRoots(absRoot),
		SkipDirRegex: regexp.MustCompile(`(^|[\\/])\.git$`),
		MaxFileSize:  DefaultMaxFileSize * 8,
		ReadSymlinks: false,
		Stats:        stats.NoopCollector{},
	}
	packages, _, err := filesystem.Run(ctx, run)
	if err != nil {
		return nil, nil, fmt.Errorf("artifact extraction failed: %w", err)
	}
	var components []Component
	identified := map[string]bool{}
	for _, pkg := range packages.Packages {
		component, ok := toComponent(pkg)
		if !ok {
			continue
		}
		// package.json only counts for installed packages; a project's own
		// manifest is not a dependency.
		if component.Extractor == packagejson.Name && !strings.Contains(component.Path, "node_modules/") {
			continue
		}
		// A jar without Maven metadata gets a name from its file name and no
		// group: that is a guess, listed as not identified instead.
		if component.Extractor == archive.Name && (component.Version == "" || !strings.Contains(component.Name, ":")) {
			continue
		}
		component.Resolution = ResolutionArtifact
		if component.Extractor == dpkg.Name || component.Extractor == apk.Name || component.Extractor == rpm.Name {
			component.Relationship = RelationshipUnknown
		}
		identified[component.Path] = true
		components = append(components, component)
	}
	var unidentified []Unidentified
	_ = filepath.WalkDir(absRoot, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(absRoot, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if identified[rel] || IsManifestPath(rel) {
			return nil
		}
		kind := fileType(p)
		if kind == "" {
			return nil // text, data, documentation
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		unidentified = append(unidentified, Unidentified{Path: rel, Size: info.Size(), Type: kind})
		return nil
	})
	// A jar whose metadata the extractor read is identified through the
	// components that name it as their path.
	return components, unidentified, nil
}

func (inv *ArtifactInventory) addUnidentified(entries []Unidentified, opts ScanOptions) {
	for _, entry := range entries {
		inv.UnidentifiedCount++
		if len(inv.Unidentified) < opts.KeepUnidentified {
			inv.Unidentified = append(inv.Unidentified, entry)
		}
	}
}

// classifyFile decides how a file target is read.
func classifyFile(target string) string {
	base := filepath.Base(target)
	if IsManifestPath(base) {
		return KindManifest
	}
	ext := extensionOf(target)
	if archiveExtensions[ext] {
		return KindArchive
	}
	if strings.HasSuffix(strings.ToLower(base), ".json") || strings.HasSuffix(strings.ToLower(base), ".cdx") || strings.HasSuffix(strings.ToLower(base), ".spdx") {
		if data, err := os.ReadFile(target); err == nil && looksLikeSBOM(data) { // #nosec G304 -- a file the user named
			return KindSBOM
		}
	}
	if isBinary(target) {
		return KindBinary
	}
	return "unidentified"
}

func extensionOf(target string) string {
	lower := strings.ToLower(target)
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz"} {
		if strings.HasSuffix(lower, ext) {
			return ext
		}
	}
	return strings.ToLower(filepath.Ext(target))
}

func looksLikeSBOM(data []byte) bool {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
	}
	return json.Unmarshal(data, &probe) == nil && (probe.BomFormat == "CycloneDX" || probe.SpdxVersion != "")
}

// componentsFromSBOM reads an SBOM file as a source of components.
func componentsFromSBOM(data []byte, file string) ([]Component, error) {
	var parsed []sbom.ParsedComponent
	var probe struct {
		BomFormat string `json:"bomFormat"`
	}
	_ = json.Unmarshal(data, &probe)
	var err error
	if probe.BomFormat == "CycloneDX" {
		parsed, err = sbom.ParseCycloneDXJSON(data)
	} else {
		parsed, err = sbom.ParseSPDXJSON(data)
	}
	if err != nil {
		return nil, err
	}
	out := make([]Component, 0, len(parsed))
	for _, p := range parsed {
		if p.PURL == "" {
			continue
		}
		relationship := RelationshipUnknown
		for _, value := range p.Properties[PropertyRelationship] {
			relationship = Relationship(value)
		}
		out = append(out, Component{
			Purl:         p.PURL,
			Name:         p.Name,
			Version:      p.Version,
			Ecosystem:    p.Ecosystem,
			Relationship: relationship,
			Resolution:   ResolutionRecorded,
			Scopes:       p.Properties[PropertyScope],
			Path:         file,
			Module:       moduleOf(file),
			Extractor:    "sbom",
		})
	}
	return out, nil
}

var binaryMagic = [][]byte{
	{0x7f, 'E', 'L', 'F'},
	{'M', 'Z'},
	{0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe},
}

func isBinary(target string) bool {
	f, err := os.Open(target) // #nosec G304 -- a file the user named
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	for _, magic := range binaryMagic {
		if n >= len(magic) && bytes.Equal(head[:len(magic)], magic) {
			return true
		}
	}
	return false
}

var textExtensions = map[string]bool{
	".txt": true, ".md": true, ".json": true, ".yaml": true, ".yml": true, ".xml": true, ".properties": true, ".html": true, ".css": true,
	".svg": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true,
	".map": true, ".ts": true, ".java": true, ".py": true, ".go": true, ".rs": true, ".kt": true, ".sh": true, ".conf": true, ".cfg": true,
	".ini": true, ".toml": true, ".lock": true, ".sql": true, ".csv": true, ".pdf": true, ".license": true, ".mf": true, ".sf": true, ".rsa": true, ".dsa": true,
	".class": true, ".pem": true, ".crt": true, ".list": true, ".idx": true, ".pack": true, ".pyc": true, ".h": true, ".c": true, ".cpp": true,
}

// fileType names a file worth reporting as not identified: native
// libraries, executables, jars without metadata, bundles. Text and data
// return "".
func fileType(p string) string {
	ext := strings.ToLower(filepath.Ext(p))
	switch ext {
	case ".dll", ".so", ".dylib", ".a", ".lib":
		return "native library"
	case ".exe", ".bin", ".wasm", ".node", ".pyd":
		return "executable"
	case ".jar", ".war", ".ear", ".aar":
		return "java archive without Maven metadata"
	case ".js", ".mjs", ".cjs":
		if strings.Contains(strings.ToLower(filepath.Base(p)), ".min.") || strings.Contains(p, "/dist/") || strings.Contains(p, "/build/") {
			return "javascript bundle"
		}
		return ""
	case ".whl", ".egg", ".nupkg", ".gem", ".zip", ".tgz", ".tar", ".gz":
		return "archive"
	case "":
		if isBinary(p) {
			return "executable"
		}
		return ""
	}
	if textExtensions[ext] {
		return ""
	}
	if strings.Contains(ext, ".so.") || regexp.MustCompile(`\.so\.\d`).MatchString(strings.ToLower(p)) {
		return "native library"
	}
	return ""
}

// unpackArchive extracts a zip or tar into root with the limits of
// ADR-046 §7: no path outside root, no symlinks, bounded bytes and
// entries, nested archives up to MaxDepth. Returns the entry count.
func unpackArchive(source, root string, opts ScanOptions, depth int) (int, error) {
	if depth > opts.MaxDepth {
		opts.Warn(fmt.Sprintf("%s: nested deeper than %d archives, not unpacked", source, opts.MaxDepth))
		return 0, nil
	}
	ext := extensionOf(source)
	var entries int
	var total int64
	var err error
	switch ext {
	case ".zip", ".whl", ".egg", ".nupkg":
		entries, total, err = unpackZip(source, root, opts)
	case ".tar", ".tgz", ".tar.gz":
		entries, total, err = unpackTar(source, root, opts, ext != ".tar")
	default:
		return 0, fmt.Errorf("unsupported archive %s", ext)
	}
	if err != nil {
		return entries, err
	}
	_ = total
	// Nested archives (zip in zip, tgz in zip) are unpacked next to their
	// name with a "!" suffix so paths read "outer.zip!/inner.tgz!/file".
	nested := 0
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		e := extensionOf(p)
		if !archiveExtensions[e] || javaArchiveExtensions[e] {
			return nil
		}
		if strings.HasSuffix(filepath.Dir(p), "!") {
			return nil
		}
		target := p + "!"
		if _, err := os.Stat(target); err == nil {
			return nil
		}
		if err := os.MkdirAll(target, 0o750); err != nil { // #nosec G122 -- a directory next to the entry inside the temp root this process created; symlinks are never materialised
			return nil
		}
		n, err := unpackArchive(p, target, opts, depth+1)
		if err != nil {
			opts.Warn(fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		nested += n
		return nil
	})
	return entries + nested, nil
}

func safeJoin(root, entryName string) (string, error) {
	cleaned := filepath.Clean("/" + filepath.FromSlash(entryName))
	target := filepath.Join(root, cleaned)
	if !strings.HasPrefix(target, filepath.Clean(root)+string(os.PathSeparator)) && target != filepath.Clean(root) {
		return "", fmt.Errorf("entry %q escapes the archive root", entryName)
	}
	return target, nil
}

func unpackZip(source, root string, opts ScanOptions) (int, int64, error) {
	reader, err := zip.OpenReader(source)
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()
	var entries int
	var total int64
	for _, file := range reader.File {
		if entries >= opts.MaxEntries {
			return entries, total, fmt.Errorf("more than %d entries", opts.MaxEntries)
		}
		mode := file.Mode()
		if mode&os.ModeSymlink != 0 {
			continue
		}
		target, err := safeJoin(root, file.Name)
		if err != nil {
			return entries, total, err
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return entries, total, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return entries, total, err
		}
		rc, err := file.Open()
		if err != nil {
			return entries, total, err
		}
		n, err := writeLimited(target, rc, opts.MaxArchiveBytes-total)
		_ = rc.Close()
		if err != nil {
			return entries, total, err
		}
		total += n
		entries++
	}
	return entries, total, nil
}

func unpackTar(source, root string, opts ScanOptions, gzipped bool) (int, int64, error) {
	f, err := os.Open(source) // #nosec G304 -- a file the user named
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var reader io.Reader = f
	if gzipped {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, 0, err
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	var entries int
	var total int64
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return entries, total, err
		}
		if entries >= opts.MaxEntries {
			return entries, total, fmt.Errorf("more than %d entries", opts.MaxEntries)
		}
		target, err := safeJoin(root, header.Name)
		if err != nil {
			return entries, total, err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return entries, total, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return entries, total, err
			}
			n, err := writeLimited(target, tr, opts.MaxArchiveBytes-total)
			if err != nil {
				return entries, total, err
			}
			total += n
			entries++
		default:
			// Symlinks, devices, hard links: never materialised.
		}
	}
	return entries, total, nil
}

func writeLimited(target string, r io.Reader, remaining int64) (int64, error) {
	if remaining <= 0 {
		return 0, errors.New("archive exceeds the size budget")
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- inside the temp root, checked by safeJoin
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(r, remaining+1))
	if err != nil {
		return n, err
	}
	if n > remaining {
		return n, errors.New("archive exceeds the size budget")
	}
	// Executables keep their bit so the Go binary extractor looks at them.
	if isBinary(target) {
		_ = os.Chmod(target, 0o700)
	}
	return n, nil
}

func copyFile(source, target string) error {
	in, err := os.Open(source) // #nosec G304 -- a file the user named
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	mode := info.Mode().Perm() | 0o600
	if isBinary(source) {
		mode |= 0o100
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec G304 -- inside the temp root
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p) // #nosec G304 -- a file the user named
	if err != nil {
		return "", err
	}
	defer f.Close()
	return sha256Of(f)
}

// dedupeComponents merges identical (purl, path) entries.
func dedupeComponents(components []Component) []Component {
	seen := make(map[string]bool, len(components))
	out := make([]Component, 0, len(components))
	for _, c := range components {
		key := c.Purl + "|" + c.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// ---- Container images (ADR-045 §10, C2 and C3) ----

// ImageInventory is a scanned image.
type ImageInventory struct {
	Reference string            `json:"reference"`
	Digest    string            `json:"digest,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Inventory *ArtifactInventory
}

// ScanImage analyses a container image: a local tarball (docker save,
// OCI layout tar) or a registry reference pulled with the user's own
// credentials. OS packages (dpkg, apk) and language packages of every
// layer are read from the squashed filesystem; layer attribution is a
// later step.
func ScanImage(ctx context.Context, reference string, opts ScanOptions) (*ImageInventory, error) {
	opts = opts.withDefaults()
	var img v1.Image
	var err error
	if info, statErr := os.Stat(reference); statErr == nil && !info.IsDir() {
		img, err = tarball.ImageFromPath(reference, nil)
		if err != nil {
			return nil, fmt.Errorf("read image tarball: %w", err)
		}
	} else {
		ref, parseErr := name.ParseReference(reference)
		if parseErr != nil {
			return nil, fmt.Errorf("parse image reference: %w", parseErr)
		}
		img, err = remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("pull image %s: %w", reference, err)
		}
	}
	out := &ImageInventory{Reference: reference}
	if digest, err := img.Digest(); err == nil {
		out.Digest = digest.String()
	}
	if config, err := img.ConfigFile(); err == nil && config != nil {
		out.Labels = config.Config.Labels
	}
	fsys, err := scalibrimage.NewFromImage(img)
	if err != nil {
		return nil, fmt.Errorf("unpack image: %w", err)
	}
	root := ""
	if dir, ok := fsys.(interface{ Path() string }); ok {
		root = dir.Path()
	}
	if root == "" {
		// DirFS is a string path type in SCALIBR; recover it through its
		// textual form.
		root = strings.TrimPrefix(fmt.Sprint(fsys), "DirFS(")
		root = strings.TrimSuffix(root, ")")
	}
	defer func() { _ = os.RemoveAll(root) }()
	components, unidentified, err := extractArtifacts(ctx, root, opts)
	if err != nil {
		return nil, err
	}
	for i := range components {
		components[i].Path = reference + "!/" + components[i].Path
		components[i].Module = reference
	}
	inv := &ArtifactInventory{Components: dedupeComponents(components), Unidentified: []Unidentified{}}
	sortComponents(inv.Components)
	inv.addUnidentified(unidentified, opts)
	inv.Modules = buildModules(inv.Components)
	inv.Targets = []TargetSummary{{Path: reference, Kind: KindImage, Components: len(inv.Components), SHA256: strings.TrimPrefix(out.Digest, "sha256:"), Metadata: imageMetadata(out.Labels)}}
	out.Inventory = inv
	return out, nil
}

func imageMetadata(labels map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range labels {
		switch key {
		case "org.opencontainers.image.revision":
			out["revision"] = value
		case "org.opencontainers.image.version":
			out["version"] = value
		case "org.opencontainers.image.source":
			out["source"] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
