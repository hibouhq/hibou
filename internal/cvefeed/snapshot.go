package cvefeed

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Snapshot streams the current corpus as an uncompressed tar, returning the
// commit it came from and that commit's date.
//
// Fetches the branch rather than a resolved SHA on purpose. Fetching a bare SHA
// needs uploadpack.allowTipSHA1InWant, which is off by default in vanilla
// git-http-backend — so an internal mirror could serve the sweep and refuse the
// seed. It also removes the race between resolving a head and fetching it.
//
// Goes through the configured remote, not a vendor archive host: a mirrored
// instance has only the former. The blobs land in a throwaway clone rather than
// the sweep's 10 MB one, and closing the stream removes it.
func (g *GitSource) Snapshot(ctx context.Context) (io.ReadCloser, string, time.Time, error) {
	if err := validateRemote(g.remoteURL()); err != nil {
		return nil, "", time.Time{}, err
	}

	// TMPDIR is the pod's size-limited scratch volume under Kubernetes.
	dir, err := os.MkdirTemp("", "hibou-cve-seed-*")
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("create seed workspace: %w", err)
	}
	stream := &corpusStream{dir: dir}

	// `git archive` reads objects, so the ~3.2 GB working tree never exists.
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"remote", "add", "--", "origin", g.remoteURL()},
		{"fetch", "--quiet", "--depth", "1", "--", "origin", defaultBranch},
	} {
		if err := stream.git(ctx, args...); err != nil {
			_ = stream.Close()
			return nil, "", time.Time{}, err
		}
	}

	// Whatever the fetch actually landed on, which is also what gets recorded as
	// the resume point.
	head, err := stream.output(ctx, "rev-parse", "FETCH_HEAD")
	if err != nil {
		_ = stream.Close()
		return nil, "", time.Time{}, fmt.Errorf("resolve fetched commit: %w", err)
	}
	commit := strings.TrimSpace(head)
	if !commitPattern.MatchString(commit) {
		_ = stream.Close()
		return nil, "", time.Time{}, fmt.Errorf("cvefeed: unexpected fetched commit %q", commit)
	}

	// Read while the object is still here. Not worth failing a seed over.
	var committedAt time.Time
	if out, dateErr := stream.output(ctx, "log", "-1", "--format=%cI", commit); dateErr == nil {
		if parsed, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(out)); parseErr == nil {
			committedAt = parsed
		}
	}

	// commit is a validated hex SHA
	archive, cleanupHome, err := gitCommand(ctx, "", "-C", dir, "archive", "--format=tar", commit)
	if err != nil {
		_ = stream.Close()
		return nil, "", time.Time{}, err
	}
	stream.cleanupHome = cleanupHome
	out, err := archive.StdoutPipe()
	if err != nil {
		_ = stream.Close()
		return nil, "", time.Time{}, err
	}
	var stderr strings.Builder
	archive.Stderr = &stderr
	if err := archive.Start(); err != nil {
		_ = stream.Close()
		return nil, "", time.Time{}, fmt.Errorf("stream snapshot: %w", err)
	}
	stream.cmd = archive
	stream.stderr = &stderr
	stream.out = out
	return stream, commit, committedAt, nil
}

// corpusStream is the tar bytes plus the workspace they came from, so Close
// also frees ~300 MB.
type corpusStream struct {
	dir    string
	cmd    *exec.Cmd
	out    io.ReadCloser
	stderr *strings.Builder
	// cleanupHome removes the archive command's temporary git HOME.
	cleanupHome func()
}

func (s *corpusStream) Read(p []byte) (int, error) {
	if s.out == nil {
		return 0, io.EOF
	}
	return s.out.Read(p)
}

func (s *corpusStream) Close() error {
	var err error
	if s.out != nil {
		_ = s.out.Close()
	}
	if s.cmd != nil {
		// Waited on: an abandoned git holds the workspace's files open, which
		// on some filesystems defeats the removal below.
		if waitErr := s.cmd.Wait(); waitErr != nil && s.stderr != nil && s.stderr.Len() > 0 {
			err = fmt.Errorf("snapshot stream: %s", strings.TrimSpace(s.stderr.String()))
		}
	}
	if s.cleanupHome != nil {
		s.cleanupHome()
	}
	if removeErr := os.RemoveAll(s.dir); removeErr != nil && err == nil {
		err = removeErr
	}
	return err
}

func (s *corpusStream) git(ctx context.Context, args ...string) error {
	full := append([]string{"-C", s.dir}, args...)
	// Minimal environment: a credential prompt would hang the sweep.
	cmd, cleanup, err := gitCommand(ctx, "", full...)
	if err != nil {
		return err
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// output runs a read-only git command in the workspace and returns its stdout.
func (s *corpusStream) output(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-C", s.dir}, args...)
	cmd, cleanup, err := gitCommand(ctx, "", full...)
	if err != nil {
		return "", err
	}
	defer cleanup()
	out, err := cmd.Output()
	return string(out), err
}
