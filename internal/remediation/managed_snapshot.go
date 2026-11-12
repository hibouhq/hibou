package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// ManagedSnapshot contains dependency data, never Git metadata or credentials.
// SourceSHA binds it to the controller's authenticated immutable checkout.
type ManagedSnapshot struct {
	SourceSHA string            `json:"source_sha"`
	Files     map[string][]byte `json:"files"`
}

type ManagedWorkload struct {
	Input    ManagedInput    `json:"input"`
	Snapshot ManagedSnapshot `json:"snapshot"`
}

// SelectManagedSnapshot excludes unselected modules and their configuration
// (which may contain secrets) from generation/verification workloads.
func SelectManagedSnapshot(snapshot ManagedSnapshot, units []Unit) (ManagedSnapshot, error) {
	selected := ManagedSnapshot{SourceSHA: snapshot.SourceSHA, Files: map[string][]byte{}}
	if len(units) == 0 || len(units) > MaxUnits {
		return selected, errors.New("managed execution requires selected resolution units")
	}
	for _, unit := range units {
		for _, name := range unit.RequiredFiles {
			data, exists := snapshot.Files[name]
			if !exists || !IsInputPath(name) || unit.InputSHA256[name] != digest(data) {
				return selected, errors.New("selected source differs from committed discovery hashes")
			}
			selected.Files[name] = data
		}
	}
	return selected, nil
}

func CaptureManagedSnapshot(ctx context.Context, repository, sha string) (ManagedSnapshot, error) {
	result := ManagedSnapshot{SourceSHA: sha, Files: map[string][]byte{}}
	if !validSHA(sha) {
		return result, errors.New("managed source requires a full immutable SHA")
	}
	listing, err := gitOutput(ctx, repository, repository, "ls-tree", "-r", "--name-only", "-z", sha)
	if err != nil {
		return result, err
	}
	total := 0
	for _, file := range strings.Split(string(listing), "\x00") {
		if !IsInputPath(file) {
			continue
		}
		if !safePath(file) || len(result.Files) >= MaxFiles {
			return result, errors.New("managed source contains an unsafe path or too many dependency files")
		}
		mode, err := gitOutput(ctx, repository, repository, "ls-tree", sha, "--", file)
		if err != nil || !bytes.HasPrefix(mode, []byte("100644 blob ")) {
			return result, fmt.Errorf("managed source %q is not a regular non-executable file", file)
		}
		data, err := gitOutput(ctx, repository, repository, "cat-file", "blob", sha+":"+file)
		if err != nil {
			return result, err
		}
		total += len(data)
		if len(data) > MaxFileBytes || total > MaxInputBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return result, errors.New("managed dependency source exceeds text/size limits")
		}
		result.Files[file] = data
	}
	return result, nil
}

// MaterializeManagedSnapshot gives the existing Git-based engine a disposable
// local commit. Its synthetic SHA is never used as the forge/publication SHA.
func MaterializeManagedSnapshot(ctx context.Context, snapshot ManagedSnapshot, scratch string) (string, string, func(), error) {
	if !validSHA(snapshot.SourceSHA) || len(snapshot.Files) == 0 || len(snapshot.Files) > MaxFiles {
		return "", "", nil, errors.New("invalid or empty managed snapshot")
	}
	root, err := os.MkdirTemp(scratch, "hibou-input-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	fail := func(err error) (string, string, func(), error) {
		cleanup()
		return "", "", nil, err
	}
	total := 0
	for file, data := range snapshot.Files {
		total += len(data)
		if !safePath(file) || !IsInputPath(file) || len(data) > MaxFileBytes || total > MaxInputBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return fail(errors.New("invalid managed snapshot dependency file"))
		}
		target := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return fail(err)
		}
	}
	if _, err := gitOutput(ctx, root, root, "init", "--quiet"); err != nil {
		return fail(err)
	}
	if _, err := gitOutput(ctx, root, root, "add", "--", "."); err != nil {
		return fail(err)
	}
	tree, err := gitOutput(ctx, root, root, "write-tree")
	if err != nil {
		return fail(err)
	}
	commit, err := gitOutput(ctx, root, root, "-c", "user.name=Hibou", "-c", "user.email=workload@hibou.invalid", "commit-tree", strings.TrimSpace(string(tree)), "-m", "Dependency input snapshot")
	if err != nil {
		return fail(err)
	}
	return root, strings.TrimSpace(string(commit)), cleanup, nil
}

// VerifyManagedCandidate never accepts a worker's verification booleans as
// evidence. The controller repeats patch/hash/graph/policy checks without
// native tools; a fresh verification workload additionally runs npm ci.
func VerifyManagedCandidate(ctx context.Context, repository string, input ManagedInput, result *ManagedResult, backend NPMBackend, native bool) error {
	if result == nil || result.Artifact == nil || result.Error != "" || result.Unavailable != "" {
		return errors.New("managed candidate is incomplete or failed")
	}
	artifact := result.Artifact
	if err := ValidateManagedArtifact(input, artifact); err != nil {
		return err
	}
	if err := ValidateManagedFiles(artifact, result.Files); err != nil {
		return err
	}
	reconstructed, err := managedArtifactFiles(ctx, repository, filepath.Dir(repository), *artifact)
	if err != nil {
		return err
	}
	for name, data := range result.Files {
		if !bytes.Equal(data, reconstructed[name]) {
			return errors.New("candidate files differ from patch reconstruction")
		}
	}
	root, err := os.MkdirTemp(filepath.Dir(repository), "hibou-candidate-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(root) }()
	for i, unit := range input.Units {
		if managedNPMControlReason(unit.Manifest, unit.RequiredFiles) != "" {
			return errors.New("candidate includes unapproved manager/runtime controls")
		}
		for _, name := range unit.RequiredFiles {
			data, err := gitOutput(ctx, repository, root, "cat-file", "blob", input.BaseSHA+":"+name)
			if err != nil || unit.InputSHA256[name] != digest(data) {
				return errors.New("candidate source differs from discovery hashes")
			}
			target := filepath.Join(root, filepath.FromSlash(name))
			if !safePath(name) || !IsInputPath(name) {
				return errors.New("candidate contains unsafe dependency input")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(target, data, 0o600); err != nil {
				return err
			}
		}
		before, err := readNPMProject(root, unit, backend.Tool)
		if err != nil {
			return err
		}
		for _, name := range unit.WritableFiles {
			if data, changed := result.Files[name]; changed {
				if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0o600); err != nil {
					return err
				}
			}
		}
		after, err := readNPMProject(root, unit, backend.Tool)
		if err != nil {
			return err
		}
		bound := UnitResult{ID: unit.ID, baseline: before, RequestedTargets: slices.Clone(unit.VersionTargets)}
		var verified Verification
		if native {
			verified, err = backend.Verify(ctx, root, unit, bound)
		} else {
			verified, err = backend.verifyGraph(ctx, unit, bound, after)
		}
		if err != nil {
			return fmt.Errorf("independent verification of %s: %w", unit.ID, err)
		}
		artifact.Verification[i] = verified
		beforeByPath := make(map[string]npmPackage, len(before))
		for _, pkg := range before {
			beforeByPath[pkg.Path] = pkg
		}
		bound.Updates = []Update{}
		for _, pkg := range after {
			if previous, ok := beforeByPath[pkg.Path]; ok && previous.Version != pkg.Version {
				bound.Updates = append(bound.Updates, Update{Name: pkg.Name, From: previous.Version, To: pkg.Version})
			}
		}
		artifact.Units[i] = bound
	}
	return nil
}
