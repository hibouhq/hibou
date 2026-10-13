package lsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
)

// maxShowBytes bounds `git show <sha>:<file>`. Larger files get identity line
// mapping, like a file whose scanned content is unknown.
const maxShowBytes = 8 << 20

// git runs git commands in one working tree. Commands never prompt and never
// take optional locks, so the server cannot block on, or interfere with, the
// user's own git operations.
type git struct {
	root string
}

func (g git) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"--no-optional-locks", "-C", g.root}, args...)
	cmd := exec.CommandContext(ctx, "git", full...) // #nosec G204 -- fixed git subcommands; arguments are commit SHAs and repo-relative paths, passed as argv, never through a shell.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.Bytes(), fmt.Errorf("git %s: exit %d: %s", args[0], exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}

func (g git) output(ctx context.Context, args ...string) (string, error) {
	out, err := g.run(ctx, args...)
	return strings.TrimSpace(string(out)), err
}

// findRepoRoot returns the top-level directory of the work tree containing dir.
func findRepoRoot(ctx context.Context, dir string) (string, error) {
	return git{root: dir}.output(ctx, "rev-parse", "--show-toplevel")
}

func (g git) head(ctx context.Context) (string, error) {
	return g.output(ctx, "rev-parse", "HEAD")
}

// branch returns the checked-out branch, or "" on a detached HEAD.
func (g git) branch(ctx context.Context) string {
	name, err := g.output(ctx, "symbolic-ref", "--short", "-q", "HEAD")
	if err != nil {
		return ""
	}
	return name
}

// remoteURL returns the URL of the branch's upstream remote, else "origin",
// else the first configured remote.
func (g git) remoteURL(ctx context.Context, branch string) (string, error) {
	var candidates []string
	if branch != "" {
		if remote, err := g.output(ctx, "config", "--get", "branch."+branch+".remote"); err == nil && remote != "" && remote != "." {
			candidates = append(candidates, remote)
		}
	}
	candidates = append(candidates, "origin")
	if all, err := g.output(ctx, "remote"); err == nil {
		candidates = append(candidates, strings.Fields(all)...)
	}
	for _, remote := range candidates {
		if u, err := g.output(ctx, "remote", "get-url", remote); err == nil && u != "" {
			return u, nil
		}
	}
	return "", errors.New("the repository has no git remote")
}

// isAncestor reports whether sha is an ancestor of (or equal to) head. An
// unknown commit (shallow clone, not fetched) is reported as not an ancestor.
func (g git) isAncestor(ctx context.Context, sha, head string) (bool, error) {
	_, err := g.run(ctx, "merge-base", "--is-ancestor", sha, head)
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return false, nil
}

// show returns a file's content at a commit, or ok=false when the file did
// not exist there or is too large to diff.
func (g git) show(ctx context.Context, sha, relPath string) (string, bool) {
	size, err := g.output(ctx, "cat-file", "-s", sha+":"+relPath)
	if err != nil {
		return "", false
	}
	if n, err := strconv.Atoi(size); err != nil || n > maxShowBytes {
		return "", false
	}
	out, err := g.run(ctx, "cat-file", "blob", sha+":"+relPath)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// remote is a parsed git remote URL.
type remote struct {
	Host string // lower-case host without port
	// Owner is everything between the host and the repository name: a GitHub
	// owner, a Forgejo org, or a GitLab group path ("group/subgroup").
	Owner string
	Repo  string
}

// parseRemote parses https, ssh and scp-like ("git@host:owner/repo.git")
// remote URLs.
func parseRemote(raw string) (remote, error) {
	raw = strings.TrimSpace(raw)
	var host, p string
	switch {
	case strings.Contains(raw, "://"):
		u, err := url.Parse(raw)
		if err != nil {
			return remote{}, errors.New("unparseable remote URL")
		}
		host, p = u.Hostname(), u.Path
	case strings.Contains(raw, ":"):
		// scp-like syntax: [user@]host:path
		hostPart, pathPart, _ := strings.Cut(raw, ":")
		if i := strings.LastIndex(hostPart, "@"); i >= 0 {
			hostPart = hostPart[i+1:]
		}
		host, p = hostPart, pathPart
	default:
		return remote{}, errors.New("remote is a local path, not a forge URL")
	}
	p = strings.Trim(path.Clean("/"+p), "/")
	p = strings.TrimSuffix(p, ".git")
	owner, repo := path.Split(p)
	owner = strings.Trim(owner, "/")
	if host == "" || owner == "" || repo == "" {
		return remote{}, errors.New("remote URL has no owner/repository path")
	}
	return remote{Host: strings.ToLower(host), Owner: owner, Repo: repo}, nil
}
