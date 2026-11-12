package remediation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

type ApplyResult struct {
	AlreadyApplied bool `json:"already_applied"`
}

// Apply applies a complete reviewed artifact to a matching clean file set.
// IDE callers must additionally reject unsaved buffers and coordinate edits
// while this operation is in flight. Unrelated local changes are preserved.
func Apply(ctx context.Context, repository string, artifact Artifact) (*ApplyResult, error) {
	if !validSHA(artifact.BaseSHA) || len(artifact.Patch) == 0 || len(artifact.Patch) > MaxPatchBytes || !utf8.Valid(artifact.Patch) ||
		digest(artifact.Patch) != artifact.SHA256 || len(artifact.Changes) == 0 || len(artifact.Changes) > MaxFiles {
		return nil, errors.New("invalid or corrupted remediation artifact")
	}
	if len(artifact.Units) == 0 || len(artifact.Units) != len(artifact.Verification) {
		return nil, errors.New("artifact lacks verification for its resolution units")
	}
	for _, v := range artifact.Verification {
		if !v.DependencyFilesConsistent || !v.SelectedVulnsAddressed || !v.NoIntroducedVulns {
			return nil, errors.New("artifact has incomplete verification")
		}
	}
	home, err := os.MkdirTemp("", "hibou-remediation-apply-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	sha, err := gitOutput(ctx, repository, home, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(sha)) != artifact.BaseSHA {
		return nil, errors.New("HEAD changed since generation; regenerate the patch")
	}
	seen := map[string]bool{}
	var paths []string
	afterCount := 0
	for _, change := range artifact.Changes {
		if !safePath(change.Path) || seen[change.Path] {
			return nil, errors.New("artifact has unsafe or duplicate paths")
		}
		seen[change.Path] = true
		paths = append(paths, change.Path)
		info, err := os.Lstat(filepath.Join(repository, filepath.FromSlash(change.Path)))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 || info.Size() > MaxFileBytes {
			return nil, fmt.Errorf("affected file %q is missing, unsafe or too large", change.Path)
		}
		// Lstat of the leaf is not enough: a directory could have become a link.
		for dir := filepath.Dir(change.Path); dir != "."; dir = filepath.Dir(dir) {
			parent, err := os.Lstat(filepath.Join(repository, filepath.FromSlash(dir)))
			if err != nil || !parent.IsDir() {
				return nil, fmt.Errorf("affected path %q has an unsafe parent", change.Path)
			}
		}
		data, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(change.Path)))
		if err != nil {
			return nil, err
		}
		switch digest(data) {
		case change.After:
			afterCount++
		case change.Before:
		default:
			return nil, fmt.Errorf("affected file %q has local changes; nothing was applied", change.Path)
		}
	}
	if afterCount == len(artifact.Changes) {
		return &ApplyResult{AlreadyApplied: true}, nil
	}
	if afterCount != 0 {
		return nil, errors.New("mixed applied/unapplied file state; inspect changes before retrying")
	}
	if _, err := gitOutput(ctx, repository, home, append([]string{"diff", "--cached", "--quiet", artifact.BaseSHA, "--"}, paths...)...); err != nil {
		return nil, errors.New("affected files have staged changes; nothing was applied")
	}
	if _, err := verifyPatchContents(ctx, repository, home, artifact); err != nil {
		return nil, err
	}
	if _, err := runGit(ctx, repository, home, artifact.Patch, "apply", "--check", "-"); err != nil {
		return nil, fmt.Errorf("patch does not apply; nothing was changed: %w", err)
	}
	if _, err := runGit(ctx, repository, home, artifact.Patch, "apply", "-"); err != nil {
		return nil, fmt.Errorf("apply outcome requires inspection; do not retry blindly: %w", err)
	}
	for _, change := range artifact.Changes {
		data, err := os.ReadFile(filepath.Join(repository, filepath.FromSlash(change.Path)))
		if err != nil || digest(data) != change.After {
			return nil, fmt.Errorf("apply outcome requires inspection for %q", change.Path)
		}
	}
	return &ApplyResult{}, nil
}

func verifyPatchContents(ctx context.Context, source, home string, artifact Artifact) (map[string][]byte, error) {
	root := filepath.Join(home, "verify")
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, err
	}
	for _, change := range artifact.Changes {
		if !safePath(change.Path) {
			return nil, errors.New("unsafe artifact path")
		}
		mode, err := gitOutput(ctx, source, home, "ls-tree", artifact.BaseSHA, "--", change.Path)
		if err != nil || !strings.HasPrefix(string(mode), "100644 blob ") {
			return nil, errors.New("artifact targets an unsupported base file mode")
		}
		data, err := gitOutput(ctx, source, home, "cat-file", "blob", artifact.BaseSHA+":"+change.Path)
		if err != nil {
			return nil, err
		}
		if len(data) > MaxFileBytes || digest(data) != change.Before {
			return nil, errors.New("artifact input hashes do not match its commit")
		}
		file := filepath.Join(root, filepath.FromSlash(change.Path))
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(file, data, 0o600); err != nil {
			return nil, err
		}
	}
	if _, err := gitOutput(ctx, root, home, "init", "--quiet"); err != nil {
		return nil, err
	}
	if _, err := gitOutput(ctx, root, home, "add", "."); err != nil {
		return nil, err
	}
	if _, err := runGit(ctx, root, home, artifact.Patch, "apply", "-"); err != nil {
		return nil, fmt.Errorf("invalid artifact patch: %w", err)
	}
	listing, err := gitOutput(ctx, root, home, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z")
	if err != nil {
		return nil, err
	}
	changed := strings.Split(strings.TrimSuffix(string(listing), "\x00"), "\x00")
	var expected []string
	files := make(map[string][]byte, len(artifact.Changes))
	total := 0
	for _, change := range artifact.Changes {
		expected = append(expected, change.Path)
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(change.Path)))
		if err != nil || !info.Mode().IsRegular() || (info.Mode().Perm() != 0o644 && info.Mode().Perm() != 0o600) || info.Size() > MaxFileBytes {
			return nil, fmt.Errorf("artifact output %q is unsafe", change.Path)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(change.Path)))
		if err != nil || digest(data) != change.After {
			return nil, fmt.Errorf("artifact output hash mismatch for %q", change.Path)
		}
		total += len(data)
		if total > MaxInputBytes {
			return nil, errors.New("artifact output exceeds the batch size limit")
		}
		files[change.Path] = data
	}
	slices.Sort(expected)
	slices.Sort(changed)
	if !slices.Equal(expected, changed) {
		return nil, errors.New("artifact patch changes paths outside its declared file set")
	}
	untracked, err := gitOutput(ctx, root, home, "ls-files", "--others", "-z")
	if err != nil {
		return nil, err
	}
	if len(untracked) != 0 {
		return nil, errors.New("artifact patch creates undeclared files")
	}
	return files, nil
}
