package cvefeed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"
)

// Source is where records come from.
//
// Note the fetch/read split: only the sweeper fetches, so an interactive refresh
// re-reads the pinned revision instead of taking git's lock in a handler.
type Source interface {
	// Changed returns the CVE ids whose records moved since the last call,
	// and the revision that result is current as of.
	Changed(ctx context.Context) (ids []string, revision string, err error)
	// Record returns one record's raw JSON.
	Record(ctx context.Context, cveID string) ([]byte, error)
}

// cveIDPattern guards every id that reaches a filesystem path or a URL. Ids
// come from git output and from callers, and both are treated as untrusted.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)

// ValidCVEID reports whether an id is well-formed.
func ValidCVEID(id string) bool { return cveIDPattern.MatchString(id) }

// RecordPath is the id's location in the cvelistV5 tree:
// CVE-2026-59084 → cves/2026/59xxx/CVE-2026-59084.json.
//
// The bucket is the sequence number with its last three digits replaced by
// "xxx", which is why a five-digit id lands in 59xxx and a four-digit one in
// 1xxx rather than 01xxx.
func RecordPath(cveID string) (string, error) {
	if !ValidCVEID(cveID) {
		return "", fmt.Errorf("malformed CVE id %q", cveID)
	}
	parts := strings.Split(cveID, "-")
	year, sequence := parts[1], parts[2]
	bucket := "0xxx"
	if len(sequence) > 3 {
		bucket = sequence[:len(sequence)-3] + "xxx"
	}
	return path.Join("cves", year, bucket, cveID+".json"), nil
}

// GitSource tracks the CVE list through a blobless shallow clone.
//
// A full clone is 2.6 GB; `--depth 1 --filter=blob:none --no-checkout` is 9.3 MB
// and six seconds, and record bytes are pulled on demand at ~7 KB each.
type GitSource struct {
	Dir    string // working directory for the clone
	Remote string // defaults to the public cvelistV5 repository
	// Revision is the commit the last sweep saw. Empty means "not yet swept":
	// the first Changed reports nothing and records the current head, so a
	// fresh install does not queue the entire corpus.
	Revision string
	// SeedCommit is where a first sweep resumes from instead of the current
	// head. Without it the seed and the first sweep leave a hole between them.
	//
	// A commit, never a timestamp: commit dates are not record dates, and the
	// difference loses or duplicates records at the boundary.
	SeedCommit string
	// SeedCommittedAt is that commit's date, used to deepen by date when a
	// server refuses to serve a bare SHA.
	SeedCommittedAt time.Time

	// head is the revision the last Changed resolved, and the revision records
	// are read at.
	//
	// Not FETCH_HEAD: resuming from a seed re-points FETCH_HEAD at the *old*
	// commit, so reading from it returns the corpus as it stood at seed time —
	// records added since fail outright, and records modified since come back
	// stale, which is silent.
	head string

	run runner // nil in production; tests substitute a fake git
}

type runner func(ctx context.Context, dir string, args ...string) ([]byte, error)

const defaultRemote = "https://github.com/CVEProject/cvelistV5.git"

// defaultBranch is the branch the CVE list publishes on, and the only one a
// mirror needs to carry.
const defaultBranch = "main"

// remoteURL is the operator's mirror when set, the public CVE list otherwise.
func (g *GitSource) remoteURL() string {
	if remote := strings.TrimSpace(g.Remote); remote != "" {
		return remote
	}
	return defaultRemote
}

func (g *GitSource) exec(ctx context.Context, args ...string) ([]byte, error) {
	if g.run != nil {
		return g.run(ctx, g.Dir, args...)
	}
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- args are built here, never from record content
	cmd.Dir = g.Dir
	// A clone that stops to ask for credentials would hang the worker; the
	// repository is public, so a prompt only ever means something is wrong.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return out, nil
}

// Ensure creates the clone if it is absent and is safe to call repeatedly.
func (g *GitSource) Ensure(ctx context.Context) error {
	if g.Dir == "" {
		return errors.New("cvefeed: GitSource.Dir is required")
	}
	if _, err := os.Stat(path.Join(g.Dir, ".git")); err == nil {
		return nil
	}
	if err := os.MkdirAll(g.Dir, 0o750); err != nil {
		return fmt.Errorf("create feed dir: %w", err)
	}
	remote := g.Remote
	if remote == "" {
		remote = defaultRemote
	}
	_, err := g.exec(ctx, "clone", "--depth", "1", "--filter=blob:none",
		"--no-checkout", "--quiet", remote, ".")
	return err
}

// Changed fetches and reports which CVE records moved since Revision.
//
// The first sweep (empty Revision) deliberately reports nothing: subscriptions
// are forward-looking, and back-filling a newly watched product is a handful of
// point lookups rather than a corpus-sized queue.
func (g *GitSource) Changed(ctx context.Context) ([]string, string, error) {
	if err := g.Ensure(ctx); err != nil {
		return nil, "", err
	}
	if _, err := g.exec(ctx, "fetch", "--depth", "1", "--quiet", "origin", "HEAD"); err != nil {
		return nil, "", err
	}
	headOut, err := g.exec(ctx, "rev-parse", "FETCH_HEAD")
	if err != nil {
		return nil, "", err
	}
	head := strings.TrimSpace(string(headOut))
	g.head = head
	if g.Revision == "" && strings.TrimSpace(g.SeedCommit) != "" {
		// The corpus was seeded but no sweep has run. Resume from the commit it
		// was seeded at, or the window between the two is lost.
		if resolved := g.fetchCommit(ctx, g.SeedCommit, g.SeedCommittedAt); resolved != "" {
			g.Revision = resolved
		}
	}
	if g.Revision == "" || g.Revision == head {
		return nil, head, nil
	}

	diff, err := g.exec(ctx, "diff", "--name-only", g.Revision, head)
	if err != nil {
		// A shallow history can lose the old revision entirely (the remote
		// pruned, or the clone was re-made). Re-anchoring beats reporting the
		// whole corpus as changed.
		return nil, head, nil
	}
	return cveIDsFromPaths(string(diff)), head, nil
}

// readRevision is where Record reads from: the revision the last Changed
// resolved, falling back to FETCH_HEAD when a record is read before any sweep.
func (g *GitSource) readRevision() string {
	if g.head != "" {
		return g.head
	}
	return "FETCH_HEAD"
}

// cveIDsFromPaths pulls CVE ids out of `git diff --name-only` output, ignoring
// everything in the tree that is not a record (delta.json, READMEs, schemas).
func cveIDsFromPaths(out string) []string {
	seen := map[string]struct{}{}
	ids := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "cves/") || !strings.HasSuffix(line, ".json") {
			continue
		}
		id := strings.TrimSuffix(path.Base(line), ".json")
		if !ValidCVEID(id) {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

// Record reads one record's bytes, fetching the blob on demand.
func (g *GitSource) Record(ctx context.Context, cveID string) ([]byte, error) {
	recordPath, err := RecordPath(cveID)
	if err != nil {
		return nil, err
	}
	out, err := g.exec(ctx, "show", g.readRevision()+":"+recordPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cveID, err)
	}
	if len(out) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: %s", errTooLarge, cveID)
	}
	return out, nil
}

// RemoteHead returns the commit the remote's default branch points at, without
// a local clone. One round trip, ~1 s.
//
// Chosen before the seed so the snapshot and the resume point are the same
// commit by construction.
func (g *GitSource) RemoteHead(ctx context.Context) (string, error) {
	out, err := g.exec(ctx, "ls-remote", g.remoteURL(), defaultBranch)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 || !commitPattern.MatchString(fields[0]) {
		return "", errors.New("cvefeed: unexpected ls-remote output")
	}
	return strings.ToLower(fields[0]), nil
}

// fetchCommit makes a commit available locally and returns it. The clone is
// shallow, so the seed's commit is not present until fetched.
//
// Two ways, because the direct one needs a server capability. Fetching a bare
// SHA requires uploadpack.allowReachableSHA1InWant, which GitHub sets and a
// vanilla git-http-backend mirror does not. So when that is refused and the
// commit's date is known, deepen by date instead: `--shallow-since` is ordinary
// protocol negotiation that every server supports.
//
// Full SHA only: a short ref would mean guessing which commit the corpus was
// seeded from. Returns "" when neither route works — the caller starts from
// head, which loses the window but beats refusing to run.
func (g *GitSource) fetchCommit(ctx context.Context, commit string, committedAt time.Time) string {
	if !commitPattern.MatchString(commit) {
		return ""
	}
	commit = strings.ToLower(commit)

	if _, err := g.exec(ctx, "fetch", "--quiet", "--depth", "1", "origin", commit); err == nil {
		if out, err := g.exec(ctx, "rev-parse", "FETCH_HEAD"); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	if committedAt.IsZero() {
		return ""
	}
	// An hour of slack: the boundary is exclusive and clock skew is real, and
	// fetching slightly too much history costs trees, not records.
	since := committedAt.Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := g.exec(ctx, "fetch", "--quiet", "--shallow-since="+since, "origin", defaultBranch); err != nil {
		return ""
	}
	if _, err := g.exec(ctx, "cat-file", "-e", commit+"^{commit}"); err != nil {
		return ""
	}
	return commit
}

// commitPattern matches a full commit SHA.
var commitPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
