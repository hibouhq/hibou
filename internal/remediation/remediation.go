// Package remediation generates verified dependency patches in disposable Git
// workspaces. Execution adapters supply resolution and verification; no server
// or IDE-specific policy lives here.
package remediation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	MaxFileBytes  = 16 << 20
	MaxPatchBytes = 32 << 20
	MaxFiles      = 200
	MaxUnits      = 50
	MaxInputBytes = 64 << 20
)

type Request struct {
	Repository string `json:"repository"`
	BaseSHA    string `json:"base_sha"`
	Units      []Unit `json:"units"`
}

// Unit is a complete dependency resolution boundary, not one advisory.
type Unit struct {
	ID            string   `json:"id"`
	Manager       string   `json:"manager"`
	Manifest      string   `json:"manifest"`
	Lockfile      string   `json:"lockfile,omitempty"`
	RequiredFiles []string `json:"required_files"`
	WritableFiles []string `json:"writable_files"`
	Vulns         []string `json:"vulns"`
	UpgradeLevel  string   `json:"upgrade_level"`
	// InputSHA256 binds discovery to the committed file set, including files
	// whose absence influences manager detection.
	InputSHA256    map[string]string `json:"input_sha256"`
	VersionTargets []VersionTarget   `json:"version_targets,omitempty"`
	DirectPackages []DirectPackage   `json:"direct_packages,omitempty"`
}

type Update struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

type UnitResult struct {
	ID               string   `json:"id"`
	Updates          []Update `json:"updates"`
	baseline         []npmPackage
	RequestedTargets []VersionTarget `json:"requested_targets,omitempty"`
}

type Verification struct {
	// All three are mandatory. Build/test execution is deliberately separate.
	DependencyFilesConsistent bool `json:"dependency_files_consistent"`
	SelectedVulnsAddressed    bool `json:"selected_vulns_addressed"`
	NoIntroducedVulns         bool `json:"no_introduced_vulns"`
}

type Change struct {
	Path   string `json:"path"`
	Before string `json:"before_sha256"`
	After  string `json:"after_sha256"`
}

type Artifact struct {
	BaseSHA      string         `json:"base_sha"`
	SHA256       string         `json:"sha256"`
	Patch        []byte         `json:"patch"`
	Changes      []Change       `json:"changes"`
	Units        []UnitResult   `json:"units"`
	Verification []Verification `json:"verification"`
}

// Backend runs only in an explicitly trusted local or isolated environment.
// Validate must reject unsupported manager/lockfile/version combinations.
type Backend interface {
	Validate(Unit) error
	Generate(context.Context, string, Unit) (UnitResult, error)
	Verify(context.Context, string, Unit, UnitResult) (Verification, error)
}

type Engine struct {
	Backend Backend
	TempDir string
}

var ErrNoChanges = errors.New("remediation produced no dependency-file changes")

// Generate never changes the source working tree or returns a partial artifact.
func (e Engine) Generate(ctx context.Context, req Request) (*Artifact, error) {
	if e.Backend == nil {
		return nil, errors.New("remediation backend is required")
	}
	files, writable, err := validateRequest(req, e.Backend)
	if err != nil {
		return nil, err
	}
	home, err := os.MkdirTemp(e.TempDir, "hibou-remediation-")
	if err != nil {
		return nil, fmt.Errorf("create remediation workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	root := filepath.Join(home, "repo")
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, err
	}
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer rootFS.Close()
	source, err := filepath.Abs(req.Repository)
	if err != nil {
		return nil, err
	}
	resolved, err := gitOutput(ctx, source, home, "rev-parse", "--verify", req.BaseSHA+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("resolve remediation base: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(string(resolved)), req.BaseSHA) {
		return nil, errors.New("resolved commit differs from requested base")
	}
	before := make(map[string][]byte, len(files))
	inputBytes := 0
	for _, file := range files {
		mode, err := gitOutput(ctx, source, home, "ls-tree", req.BaseSHA, "--", file)
		if err != nil {
			return nil, err
		}
		// Reject executable files, symlinks, submodules and missing paths.
		if !bytes.HasPrefix(mode, []byte("100644 blob ")) {
			return nil, fmt.Errorf("dependency input %q must be a tracked regular non-executable file", file)
		}
		data, err := gitOutput(ctx, source, home, "cat-file", "blob", req.BaseSHA+":"+file)
		if err != nil {
			return nil, fmt.Errorf("read dependency input %s: %w", file, err)
		}
		if len(data) > MaxFileBytes || bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return nil, fmt.Errorf("dependency input %q is too large or binary", file)
		}
		inputBytes += len(data)
		if inputBytes > MaxInputBytes {
			return nil, errors.New("dependency inputs exceed the batch size limit")
		}
		before[file] = data
		target := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, err
		}
		if err := rootFS.WriteFile(file, data, 0o600); err != nil {
			return nil, err
		}
	}
	gitDirectory := filepath.Join(home, "git-metadata")
	if _, err := gitOutput(ctx, root, home, "init", "--quiet", "--separate-git-dir="+gitDirectory); err != nil {
		return nil, err
	}
	if err := os.Chmod(gitDirectory, 0o700); err != nil {
		return nil, err
	}
	if err := rootFS.Chmod(".git", 0o600); err != nil {
		return nil, err
	}
	if _, err := gitOutput(ctx, root, home, append([]string{"add", "--"}, files...)...); err != nil {
		return nil, err
	}
	indexTree, err := gitOutput(ctx, root, home, "write-tree")
	if err != nil {
		return nil, err
	}
	for _, unit := range req.Units {
		for _, file := range unit.RequiredFiles {
			if unit.InputSHA256[file] != digest(before[file]) {
				return nil, fmt.Errorf("discovery inputs changed or are unverified: %s", file)
			}
		}
		// Inspect committed paths, not just the materialized input set.
		// A sparse request must not hide a
		// committed lockfile or manager configuration from capability checks.
		listing, err := gitOutput(ctx, source, home, "ls-tree", "-r", "--name-only", "-z", req.BaseSHA, "--", path.Dir(unit.Manifest))
		if err != nil {
			return nil, err
		}
		for _, candidate := range strings.Split(string(listing), "\x00") {
			if dependencyControlFile(path.Base(candidate)) && !slices.Contains(unit.RequiredFiles, candidate) {
				return nil, fmt.Errorf("dependency input %q was omitted from resolution unit %s", candidate, unit.ID)
			}
		}
	}
	artifact := &Artifact{BaseSHA: strings.ToLower(req.BaseSHA)}
	for _, unit := range req.Units {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := e.Backend.Generate(ctx, root, unit)
		if err != nil {
			return nil, fmt.Errorf("generate unit %s: %w", unit.ID, err)
		}
		if result.ID != unit.ID {
			return nil, errors.New("backend returned an incorrect resolution unit")
		}
		artifact.Units = append(artifact.Units, result)
	}
	generatedHashes := make(map[string]string, len(files))
	for _, file := range files {
		info, err := rootFS.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileBytes {
			return nil, fmt.Errorf("required dependency input removed or unsafe: %s", file)
		}
		data, err := rootFS.ReadFile(file)
		if err != nil {
			return nil, err
		}
		generatedHashes[file] = digest(data)
	}
	// Verify after all writes so a later unit cannot invalidate an earlier check.
	for i, unit := range req.Units {
		verification, err := e.Backend.Verify(ctx, root, unit, artifact.Units[i])
		if err != nil {
			return nil, fmt.Errorf("verify unit %s: %w", unit.ID, err)
		}
		if !verification.DependencyFilesConsistent || !verification.SelectedVulnsAddressed || !verification.NoIntroducedVulns {
			return nil, fmt.Errorf("verification failed for unit %s", unit.ID)
		}
		artifact.Verification = append(artifact.Verification, verification)
	}
	outputBytes := int64(0)
	err = filepath.WalkDir(root, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if file == filepath.Join(root, ".git") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		original, exists := before[relative]
		if !exists {
			return fmt.Errorf("unexpected generated file %q", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || (info.Mode().Perm() != 0o644 && info.Mode().Perm() != 0o600) || info.Size() > MaxFileBytes {
			return fmt.Errorf("unsafe generated file %q", relative)
		}
		outputBytes += info.Size()
		if outputBytes > MaxInputBytes {
			return errors.New("generated dependency files exceed the batch size limit")
		}
		data, err := rootFS.ReadFile(relative)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return fmt.Errorf("binary dependency output %q", relative)
		}
		if digest(data) != generatedHashes[relative] {
			return fmt.Errorf("verification unexpectedly modified dependency file %q", relative)
		}
		if !bytes.Equal(original, data) {
			if !writable[relative] {
				return fmt.Errorf("backend modified read-only dependency input %q", relative)
			}
			artifact.Changes = append(artifact.Changes, Change{Path: relative, Before: digest(original), After: digest(data)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(file))); err != nil {
			return nil, fmt.Errorf("required dependency input removed: %s: %w", file, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(artifact.Changes) == 0 {
		return nil, ErrNoChanges
	}
	currentTree, err := gitOutput(ctx, root, home, "write-tree")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(indexTree, currentTree) {
		return nil, errors.New("backend modified the patch baseline index")
	}
	patch, err := gitOutput(ctx, root, home, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--full-index", "--src-prefix=a/", "--dst-prefix=b/", "--")
	if err != nil {
		return nil, err
	}
	if len(patch) == 0 || len(patch) > MaxPatchBytes {
		return nil, errors.New("generated patch is empty or exceeds the size limit")
	}
	// Check against the untouched index, not the already modified working tree.
	if _, err := runGit(ctx, root, home, patch, "apply", "--cached", "--check", "-"); err != nil {
		return nil, fmt.Errorf("check generated patch: %w", err)
	}
	slices.SortFunc(artifact.Changes, func(a, b Change) int { return strings.Compare(a.Path, b.Path) })
	artifact.Patch, artifact.SHA256 = patch, digest(patch)
	return artifact, nil
}

func validateRequest(req Request, backend Backend) ([]string, map[string]bool, error) {
	if req.Repository == "" || !validSHA(req.BaseSHA) || len(req.Units) == 0 || len(req.Units) > MaxUnits {
		return nil, nil, errors.New("repository, full base SHA and a bounded nonempty set of resolution units are required")
	}
	ids, owners := map[string]bool{}, map[string]string{}
	writable := map[string]bool{}
	var files []string
	for _, unit := range req.Units {
		if unit.ID == "" || ids[unit.ID] || len(unit.Vulns) == 0 || len(unit.WritableFiles) == 0 {
			return nil, nil, errors.New("units require unique IDs, selected vulnerabilities and writable dependency files")
		}
		ids[unit.ID] = true
		if err := backend.Validate(unit); err != nil {
			return nil, nil, fmt.Errorf("unit %s: %w", unit.ID, err)
		}
		for _, file := range unit.RequiredFiles {
			if !safePath(file) {
				return nil, nil, fmt.Errorf("invalid dependency path %q", file)
			}
			if owner, exists := owners[file]; exists && owner != unit.ID {
				return nil, nil, fmt.Errorf("units %s and %s share %s; submit one combined resolution unit", owner, unit.ID, file)
			}
			if _, exists := owners[file]; !exists {
				files = append(files, file)
			}
			owners[file] = unit.ID
			hash, err := hex.DecodeString(unit.InputSHA256[file])
			if err != nil || len(hash) != sha256.Size {
				return nil, nil, fmt.Errorf("input %q requires its discovery SHA-256", file)
			}
		}
		for _, file := range unit.WritableFiles {
			if owners[file] != unit.ID {
				return nil, nil, fmt.Errorf("writable file %q must be a required input of unit %s", file, unit.ID)
			}
			writable[file] = true
		}
		if owners[unit.Manifest] != unit.ID || (unit.Lockfile != "" && owners[unit.Lockfile] != unit.ID) {
			return nil, nil, errors.New("manifest and lockfile must belong to their resolution unit")
		}
	}
	if len(files) > MaxFiles {
		return nil, nil, errors.New("too many dependency files")
	}
	slices.Sort(files)
	return files, writable, nil
}

func dependencyControlFile(name string) bool {
	switch name {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "pnpm-workspace.yaml", "bun.lock", "bun.lockb",
		".npmrc", ".yarnrc", ".yarnrc.yml", ".nvmrc", ".node-version", ".tool-versions", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock", "pdm.lock", "pylock.toml",
		"Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "go.work", "go.work.sum", "pom.xml", "gradle.lockfile", "verification-metadata.xml",
		"composer.json", "composer.lock", "Gemfile", "Gemfile.lock", "packages.lock.json":
		return true
	}
	return strings.HasPrefix(name, "requirements") && (strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".in"))
}

func safePath(p string) bool {
	if !fs.ValidPath(p) || p == "." || strings.ContainsAny(p, "\\\x00\r\n\t") || path.Clean(p) != p {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if strings.EqualFold(segment, ".git") {
			return false
		}
	}
	return true
}

// IsInputPath identifies dependency-control files for an authorized sparse
// checkout. It is not a declaration that the file's ecosystem can be fixed.
func IsInputPath(p string) bool { return safePath(p) && dependencyControlFile(path.Base(p)) }

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
