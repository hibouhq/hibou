package secretscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestCheckout is a partial clone holding only the files a selector
// chose (ADR-045 §4.1): a blobless clone of one ref, the tree listed, the
// chosen paths checked out. It reuses the clone plumbing of secret
// scanning, with the same private HOME and env-scoped token, and it never
// runs anything from the repository.
type ManifestCheckout struct {
	// Dir is the checkout root; only the selected paths exist under it.
	Dir string
	// Commit is the commit that was listed and checked out.
	Commit string
	// Paths are the selected repository paths, sorted.
	Paths []string
	// Digest is sha256 over "blob-id path" of every selected path, in
	// order: identical inputs give an identical digest wherever they sit.
	Digest string
	// TreeTruncated is true when the listing hit the entry limit; the
	// digest then covers what was listed, and the caller must not reuse it.
	TreeTruncated bool
	cleanup       func()
}

// Close removes the checkout.
func (c *ManifestCheckout) Close() {
	if c != nil && c.cleanup != nil {
		c.cleanup()
	}
}

// maxTreeEntries bounds the listing: a tree beyond this is a monorepo
// nobody wants extracted whole, and the walk stops with TreeTruncated.
const maxTreeEntries = 500_000

// CheckoutManifests clones ref from cloneURL without blobs, lists its tree,
// and checks out the paths select accepts. commit, when set, must be
// reachable from ref: it is fetched at depth 1 and used instead of the ref
// head, so a push job extracts the commit it was enqueued for even if the
// branch moved on.
func CheckoutManifests(ctx context.Context, parentDir, cloneURL, ref, commit, authToken string, selectPath func(string) bool) (*ManifestCheckout, error) {
	tempRoot := parentDir
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	workDir, err := os.MkdirTemp(tempRoot, "hibou-dep-extract-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(workDir) }
	home := filepath.Join(workDir, scanHomeDirName)
	if err := os.Mkdir(home, 0o700); err != nil {
		cleanup()
		return nil, fmt.Errorf("create git home: %w", err)
	}
	repoDir := filepath.Join(workDir, "repo")

	cloneURL = stripURLCredentials(cloneURL)
	authEnv, err := gitAuthEnv(cloneURL, authToken)
	if err != nil {
		cleanup()
		return nil, err
	}
	commit = strings.TrimSpace(commit)
	if commit != "" && !validCommitSHA(commit) {
		cleanup()
		return nil, fmt.Errorf("invalid commit %q", truncateText(commit, 80))
	}

	args := []string{"clone", "--filter=blob:none", "--no-checkout", "--depth", "1", "--single-branch"}
	if ref = strings.TrimSpace(ref); ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, "--", cloneURL, repoDir)
	if output, err := gitCommand(ctx, home, authEnv, args...).CombinedOutput(); err != nil {
		cleanup()
		return nil, fmt.Errorf("clone repository: %w: %s", err, scrubSecrets(string(output), authToken))
	}

	target := "HEAD"
	if commit != "" {
		head, err := gitOutput(ctx, home, nil, repoDir, "rev-parse", "HEAD")
		if err != nil {
			cleanup()
			return nil, err
		}
		if !strings.EqualFold(strings.TrimSpace(head), commit) {
			if output, err := gitCommand(ctx, home, authEnv, "-C", repoDir, "fetch", "--filter=blob:none", "--depth", "1", "origin", commit).CombinedOutput(); err != nil {
				cleanup()
				return nil, fmt.Errorf("fetch commit %s: %w: %s", commit[:12], err, scrubSecrets(string(output), authToken))
			}
		}
		target = commit
	}
	resolved, err := gitOutput(ctx, home, nil, repoDir, "rev-parse", target)
	if err != nil {
		cleanup()
		return nil, err
	}
	resolved = strings.TrimSpace(resolved)

	listing, err := gitOutput(ctx, home, nil, repoDir, "ls-tree", "-r", "-z", target)
	if err != nil {
		cleanup()
		return nil, err
	}
	paths, digest, truncated := selectTreeEntries(listing, selectPath)

	if len(paths) > 0 {
		// Only the selected blobs are fetched: pathspecs from stdin,
		// NUL-separated, so a hostile file name cannot become an option.
		var spec bytes.Buffer
		for _, p := range paths {
			spec.WriteString(p)
			spec.WriteByte(0)
		}
		cmd := gitCommand(ctx, home, authEnv, "-C", repoDir, "checkout", target, "--pathspec-from-file=-", "--pathspec-file-nul", "--")
		cmd.Stdin = &spec
		if output, err := cmd.CombinedOutput(); err != nil {
			cleanup()
			return nil, fmt.Errorf("checkout manifests: %w: %s", err, scrubSecrets(string(output), authToken))
		}
	}

	return &ManifestCheckout{
		Dir:           repoDir,
		Commit:        resolved,
		Paths:         paths,
		Digest:        digest,
		TreeTruncated: truncated,
		cleanup:       cleanup,
	}, nil
}

// selectTreeEntries parses `git ls-tree -r -z` output ("<mode> <type>
// <object>\t<path>\0") and returns the selected paths with their digest.
func selectTreeEntries(listing string, selectPath func(string) bool) ([]string, string, bool) {
	type entry struct{ path, blob string }
	var selected []entry
	entries := 0
	truncated := false
	for _, record := range strings.Split(listing, "\x00") {
		if record == "" {
			continue
		}
		entries++
		if entries > maxTreeEntries {
			truncated = true
			break
		}
		meta, p, ok := strings.Cut(record, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[1] != "blob" {
			continue
		}
		if selectPath == nil || selectPath(p) {
			selected = append(selected, entry{path: p, blob: fields[2]})
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].path < selected[j].path })
	hasher := sha256.New()
	paths := make([]string, 0, len(selected))
	for _, e := range selected {
		hasher.Write([]byte(e.blob + " " + e.path + "\n"))
		paths = append(paths, e.path)
	}
	return paths, hex.EncodeToString(hasher.Sum(nil)), truncated
}

// gitOutput runs git in repoDir and returns stdout, with stderr folded into
// the error.
func gitOutput(ctx context.Context, home string, extraEnv []string, repoDir string, args ...string) (string, error) {
	full := append([]string{"-C", repoDir}, args...)
	cmd := gitCommand(ctx, home, extraEnv, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
