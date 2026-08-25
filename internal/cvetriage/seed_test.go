package cvetriage

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/cvefeed"
)

type countingStore struct {
	n       int
	records []cvefeed.Projection
}

func (c *countingStore) SaveCVERecords(_ context.Context, records []cvefeed.Projection) error {
	c.n += len(records)
	c.records = append(c.records, records...)
	return nil
}

// tarSnapshot serves a tar built in memory, standing in for git archive.
type tarSnapshot struct {
	files       map[string][]byte
	commit      string
	failWith    error
	closeCalls  int
	committedAt time.Time
}

func (t *tarSnapshot) Snapshot(_ context.Context) (io.ReadCloser, string, time.Time, error) {
	if t.failWith != nil {
		return nil, "", time.Time{}, t.failWith
	}
	var buffer bytes.Buffer
	archive := tar.NewWriter(&buffer)
	for name, body := range t.files {
		if err := archive.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, "", time.Time{}, err
		}
		if _, err := archive.Write(body); err != nil {
			return nil, "", time.Time{}, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, "", time.Time{}, err
	}
	return &countingCloser{Reader: bytes.NewReader(buffer.Bytes()), snapshot: t}, t.commit, t.committedAt, nil
}

type countingCloser struct {
	*bytes.Reader
	snapshot *tarSnapshot
}

func (c *countingCloser) Close() error {
	c.snapshot.closeCalls++
	return nil
}

func realRecord(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../cvefeed/testdata/CVE-2026-59084.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSeedImportsRecordsAndIgnoresTheRest(t *testing.T) {
	record := realRecord(t)
	snapshot := &tarSnapshot{files: map[string][]byte{
		"cves/2026/59xxx/CVE-2026-59084.json": record,
		// The tree carries more than records; none of it is a CVE.
		"cves/delta.json":      []byte(`{"numberOfChanges":3}`),
		"README.md":            []byte("# cvelistV5"),
		"cves/schema/CVE.json": []byte(`{"$schema":"x"}`),
	}}
	store := &countingStore{}

	result, err := Seed(context.Background(), snapshot, store, nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if result.Seen != 1 || result.Stored != 1 {
		t.Fatalf("got %+v, want exactly the one record", result)
	}
	if store.records[0].ID != "CVE-2026-59084" {
		t.Errorf("imported %q", store.records[0].ID)
	}
	// The snapshot holds a workspace worth hundreds of megabytes; leaking it
	// would fill the pod's scratch volume on the first seed.
	if snapshot.closeCalls != 1 {
		t.Errorf("closed the snapshot %d times, want exactly 1", snapshot.closeCalls)
	}
}

// The source reports the commit it actually fetched, and that is what becomes
// the resume point. Telling it which commit to fetch instead would reintroduce
// a race between resolving a head and fetching it.
func TestSeedReportsTheCommitItFetched(t *testing.T) {
	snapshot := &tarSnapshot{files: map[string][]byte{}, commit: "deadbeef"}
	result, err := Seed(context.Background(), snapshot, &countingStore{}, nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if result.Commit != "deadbeef" {
		t.Errorf("Commit = %q, want the fetched commit", result.Commit)
	}
}

// One malformed record in 380,000 is a data problem to look at, not a reason to
// abandon a fifteen-minute import.
func TestSeedSurvivesABadRecord(t *testing.T) {
	snapshot := &tarSnapshot{files: map[string][]byte{
		"cves/2026/59xxx/CVE-2026-59084.json": realRecord(t),
		"cves/2026/59xxx/CVE-2026-59085.json": []byte("{not json"),
	}}
	store := &countingStore{}
	result, err := Seed(context.Background(), snapshot, store, nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if result.Seen != 2 || result.Stored != 1 || result.Failed != 1 {
		t.Fatalf("got %+v, want 2 seen, 1 stored, 1 failed", result)
	}
}

func TestSeedReportsASnapshotFailure(t *testing.T) {
	snapshot := &tarSnapshot{failWith: errors.New("remote unreachable")}
	if _, err := Seed(context.Background(), snapshot, &countingStore{}, nil); err == nil {
		t.Fatal("Seed reported success on an unreachable remote")
	}
}

// Opt-in end-to-end: HIBOU_SEED_REMOTE=<url> streams a real corpus from a real
// remote. Point it at a mirror to check an air-gapped deployment, or leave it at
// the public list.
func TestSeedAgainstARealRemote(t *testing.T) {
	remote := os.Getenv("HIBOU_SEED_REMOTE")
	if remote == "" {
		t.Skip("set HIBOU_SEED_REMOTE to run")
	}
	start := time.Now()
	store := &countingStore{}
	source := &cvefeed.GitSource{Dir: t.TempDir(), Remote: remote}
	result, err := Seed(context.Background(), source, store, nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	t.Logf("commit=%s seen=%d stored=%d failed=%d took=%s", result.Commit,
		result.Seen, result.Stored, result.Failed, time.Since(start).Round(time.Second))
	if result.Seen == 0 {
		t.Fatal("streamed no records from the remote")
	}
}

// The commit's date is carried through, because "seeded an hour ago" and "the
// corpus is a week old" are different facts and only the second one tells a
// reader whether to trust an empty result.
func TestSeedCarriesTheCommitDate(t *testing.T) {
	committed := time.Date(2026, 8, 25, 9, 0, 49, 0, time.UTC)
	snapshot := &tarSnapshot{
		files:       map[string][]byte{"cves/2026/59xxx/CVE-2026-59084.json": realRecord(t)},
		committedAt: committed,
	}
	result, err := Seed(context.Background(), snapshot, &countingStore{}, nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if !result.CommittedAt.Equal(committed) {
		t.Errorf("CommittedAt = %s, want %s", result.CommittedAt, committed)
	}
}
