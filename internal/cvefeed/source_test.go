package cvefeed

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordPath(t *testing.T) {
	cases := map[string]string{
		"CVE-2026-59084": "cves/2026/59xxx/CVE-2026-59084.json",
		"CVE-2026-1234":  "cves/2026/1xxx/CVE-2026-1234.json",
		"CVE-1999-0001":  "cves/1999/0xxx/CVE-1999-0001.json",
	}
	for id, want := range cases {
		got, err := RecordPath(id)
		if err != nil {
			t.Fatalf("RecordPath(%s): %v", id, err)
		}
		if got != want {
			t.Errorf("RecordPath(%s) = %q, want %q", id, got, want)
		}
	}
}

// Ids reach a filesystem path and a URL, and they arrive from git output and
// from callers. Anything that is not a CVE id must be refused before it gets
// near either.
func TestRecordPathRejectsMalformedIDs(t *testing.T) {
	for _, id := range []string{
		"", "CVE-2026", "cve-2026-1234", "CVE-20x6-1234",
		"../../etc/passwd", "CVE-2026-1234/../../../etc/passwd",
		"CVE-2026-1234.json", "GHSA-cwxf-7cw2-7r32",
	} {
		if _, err := RecordPath(id); err == nil {
			t.Errorf("RecordPath(%q) accepted a malformed id", id)
		}
	}
}

func TestCVEIDsFromPaths(t *testing.T) {
	out := strings.Join([]string{
		"cves/2026/59xxx/CVE-2026-59084.json",
		"cves/2026/59xxx/CVE-2026-59083.json",
		"cves/2026/59xxx/CVE-2026-59084.json", // duplicate
		"cves/delta.json",                     // not a record
		"README.md",
		"cves/2026/59xxx/notes.txt",
	}, "\n")

	got := cveIDsFromPaths(out)
	if len(got) != 2 || got[0] != "CVE-2026-59084" || got[1] != "CVE-2026-59083" {
		t.Fatalf("cveIDsFromPaths = %v", got)
	}
}

// A real clone-fetch-diff cycle against a local repository: no network, but the
// same git plumbing the production path uses.
func TestGitSourceAgainstLocalRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()

	upstream := t.TempDir()
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(dir, rel, body string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	git(upstream, "init", "--quiet", "--initial-branch=main")
	git(upstream, "config", "user.email", "t@example.invalid")
	git(upstream, "config", "user.name", "t")
	write(upstream, "cves/2026/59xxx/CVE-2026-59084.json", `{"cveMetadata":{"cveId":"CVE-2026-59084","state":"PUBLISHED"}}`)
	git(upstream, "add", ".")
	git(upstream, "commit", "--quiet", "-m", "first")

	source := &GitSource{Dir: t.TempDir(), Remote: upstream}

	// First sweep anchors without reporting: a fresh install must not queue
	// the entire corpus.
	ids, rev, err := source.Changed(ctx)
	if err != nil {
		t.Fatalf("first Changed: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("first sweep reported %v, want nothing", ids)
	}
	if rev == "" {
		t.Fatal("first sweep recorded no revision")
	}

	// The blobless clone can still read a record, fetching the blob on demand.
	data, err := source.Record(ctx, "CVE-2026-59084")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if projection, err := Decode(data); err != nil || projection.ID != "CVE-2026-59084" {
		t.Fatalf("decoded %+v, err %v", projection, err)
	}

	// A later commit is reported, and only the record that moved.
	source.Revision = rev
	write(upstream, "cves/2026/59xxx/CVE-2026-59083.json", `{"cveMetadata":{"cveId":"CVE-2026-59083","state":"PUBLISHED"}}`)
	write(upstream, "README.md", "not a record")
	git(upstream, "add", ".")
	git(upstream, "commit", "--quiet", "-m", "second")

	ids, rev2, err := source.Changed(ctx)
	if err != nil {
		t.Fatalf("second Changed: %v", err)
	}
	if len(ids) != 1 || ids[0] != "CVE-2026-59083" {
		t.Fatalf("second sweep reported %v, want just CVE-2026-59083", ids)
	}
	if rev2 == rev {
		t.Error("revision did not advance")
	}

	// An unknown revision re-anchors rather than reporting everything as new.
	source.Revision = strings.Repeat("0", 40)
	ids, _, err = source.Changed(ctx)
	if err != nil {
		t.Fatalf("Changed with a lost revision: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("lost revision reported %d ids, want re-anchor", len(ids))
	}
}

var _ Source = (*GitSource)(nil)

// The seed commit reaches a command line, and a short ref would be ambiguous —
// resolving one means guessing at which commit the corpus was seeded from, which
// is the single thing that must not be guessed. Only a full SHA is accepted.
func TestGitSourceRejectsAnythingButAFullCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	source := &GitSource{Dir: t.TempDir()}
	for _, commit := range []string{
		"", "main", "HEAD", "--upload-pack=touch /tmp/x", "refs/tags/../../etc",
		"cve_2026-08-25", "v1.0.0",
		"045fd5b", // short ref: ambiguous
		"045fd5bf99366d9315e64edffbd5f70b06897c6",   // 39 chars
		"045fd5bf99366d9315e64edffbd5f70b06897c69z", // 41 chars
		"zzzfd5bf99366d9315e64edffbd5f70b06897c69",  // not hex
	} {
		if got := source.fetchCommit(context.Background(), commit, time.Time{}); got != "" {
			t.Errorf("fetchCommit(%q) = %q, want it refused", commit, got)
		}
	}
}

// The corpus seed stores the commit it snapshotted, and the first sweep must
// resume from it. Without that the sweep starts from the current head and drops
// every record published between the seed and the sweep — silently, because a
// sweep that reports nothing looks exactly like a quiet feed.
func TestGitSourceResumesFromTheSeedCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	upstream := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = upstream
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(upstream, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	run("init", "--quiet", "--initial-branch=main")
	run("config", "user.email", "t@example.invalid")
	run("config", "user.name", "t")
	// Serving a bare SHA to a fetch is what a commit anchor requires.
	run("config", "uploadpack.allowAnySHA1InWant", "true")

	// The commit the corpus was seeded from.
	write("cves/2026/59xxx/CVE-2026-59084.json", `{"cveMetadata":{"cveId":"CVE-2026-59084"}}`)
	run("add", ".")
	run("commit", "--quiet", "-m", "the seeded commit")
	shaOut, err := exec.CommandContext(ctx, "git", "-C", upstream, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimSpace(string(shaOut))

	// Published after the seed: the record that must not be lost.
	write("cves/2026/59xxx/CVE-2026-59083.json", `{"cveMetadata":{"cveId":"CVE-2026-59083"}}`)
	run("add", ".")
	run("commit", "--quiet", "-m", "published after the import")

	source := &GitSource{Dir: t.TempDir(), Remote: upstream, SeedCommit: sha}
	ids, _, err := source.Changed(ctx)
	if err != nil {
		t.Fatalf("Changed: %v", err)
	}
	if len(ids) != 1 || ids[0] != "CVE-2026-59083" {
		t.Fatalf("ids = %v, want only the record published after the seed commit", ids)
	}
}

// An air-gapped instance mirrors the CVE list onto an internal git server and
// sets cve_feed.remote. Both halves of seeding must follow that remote: picking
// the commit, and streaming the corpus at it. A vendor archive endpoint would
// work for exactly one deployment and fail for theirs.
func TestGitSourceSeedsFromAMirroredRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	mirror := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = mirror
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	full := filepath.Join(mirror, "cves", "2026", "59xxx")
	if err := os.MkdirAll(full, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "CVE-2026-59084.json"),
		[]byte(`{"cveMetadata":{"cveId":"CVE-2026-59084"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run("init", "--quiet", "--initial-branch=main")
	run("config", "user.email", "t@example.invalid")
	run("config", "user.name", "t")
	run("add", ".")
	run("commit", "--quiet", "-m", "mirrored corpus")

	source := &GitSource{Dir: t.TempDir(), Remote: mirror}

	stream, commit, committedAt, err := source.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !commitPattern.MatchString(commit) {
		t.Fatalf("Snapshot returned commit %q, want a full SHA", commit)
	}
	defer func() { _ = stream.Close() }()

	archive := tar.NewReader(stream)
	var found []string
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read snapshot: %v", err)
		}
		if strings.HasSuffix(header.Name, ".json") {
			found = append(found, header.Name)
		}
	}
	if len(found) != 1 || !strings.HasSuffix(found[0], "CVE-2026-59084.json") {
		t.Fatalf("snapshot contained %v, want the mirrored record", found)
	}
	// The commit's date rides along, so a reader can tell a fresh corpus from a
	// stale mirror without guessing from when the seed happened to run.
	if committedAt.IsZero() {
		t.Error("no commit date returned; the UI cannot say how current the corpus is")
	}
}

// Resuming from a seed re-points FETCH_HEAD at the *old* commit, so reading
// records from FETCH_HEAD returns the corpus as it stood at seed time: records
// added since fail outright, and records modified since come back stale — which
// nothing downstream can detect.
func TestGitSourceReadsRecordsAtHeadNotAtTheSeedCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	ctx := context.Background()
	upstream := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = upstream
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(upstream, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	run("init", "--quiet", "--initial-branch=main")
	run("config", "user.email", "t@example.invalid")
	run("config", "user.name", "t")
	run("config", "uploadpack.allowAnySHA1InWant", "true")

	// The corpus as the seed captured it.
	write("cves/2026/59xxx/CVE-2026-59084.json", `{"cveMetadata":{"cveId":"CVE-2026-59084","dateUpdated":"2026-08-01T00:00:00Z"}}`)
	run("add", ".")
	run("commit", "--quiet", "-m", "seeded state")
	shaOut, err := exec.CommandContext(ctx, "git", "-C", upstream, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	seedCommit := strings.TrimSpace(string(shaOut))

	// Afterwards: one record revised, one added.
	write("cves/2026/59xxx/CVE-2026-59084.json", `{"cveMetadata":{"cveId":"CVE-2026-59084","dateUpdated":"2026-08-25T00:00:00Z"}}`)
	write("cves/2026/59xxx/CVE-2026-59083.json", `{"cveMetadata":{"cveId":"CVE-2026-59083"}}`)
	run("add", ".")
	run("commit", "--quiet", "-m", "published after the seed")

	source := &GitSource{Dir: t.TempDir(), Remote: upstream, SeedCommit: seedCommit}
	ids, _, err := source.Changed(ctx)
	if err != nil {
		t.Fatalf("Changed: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want both the revised and the added record", ids)
	}

	// Added after the seed: unreadable from the seed commit.
	if _, err := source.Record(ctx, "CVE-2026-59083"); err != nil {
		t.Errorf("reading a record added after the seed: %v", err)
	}
	// Revised after the seed: readable either way, but stale from the seed
	// commit — the failure that reports success.
	revised, err := source.Record(ctx, "CVE-2026-59084")
	if err != nil {
		t.Fatalf("reading a revised record: %v", err)
	}
	if !strings.Contains(string(revised), "2026-08-25") {
		t.Errorf("got the seed-time copy of a revised record: %s", revised)
	}
}
