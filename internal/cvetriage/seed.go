package cvetriage

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/cvefeed"
)

// SeedResult is one import of the published corpus.
type SeedResult struct {
	Seen    int
	Stored  int
	Skipped int
	Failed  int
	// Commit the snapshot came from, and the feed's resume point.
	Commit string
	// CommittedAt is when the snapshotted commit was made upstream — how current
	// the corpus is, which the time the seed ran does not say.
	CommittedAt time.Time
	// Watermark is the newest record modification the snapshot contained.
	//
	// Informational only: the sweeper resumes from the commit the snapshot was
	// cut at, which is exact. This is derived from the records and says what the
	// import actually covered.
	Watermark time.Time
}

// SeedStore is the subset of persistence an import needs. It deliberately
// cannot queue: a seed must not put twenty years of advisories in front of a
// person.
//
// Records arrive in batches because the corpus is ~380,000 of them, and one
// transaction each turns a one-off import into a half-hour wait.
type SeedStore interface {
	SaveCVERecords(ctx context.Context, records []cvefeed.Projection) error
}

// backfillBatchSize trades retry cost against transaction overhead. Large
// enough that the per-transaction cost stops dominating, small enough that a
// failed batch is cheap to redo.
const backfillBatchSize = 500

// ErrNoCorpus is returned when the archive carries no CVE records.
var ErrNoCorpus = errors.New("cvetriage: archive contains no CVE records")

// CorpusSnapshot streams the whole corpus at one commit. Implemented by
// cvefeed.GitSource against whatever remote is configured.
type CorpusSnapshot interface {
	Snapshot(ctx context.Context) (stream io.ReadCloser, commit string, committedAt time.Time, err error)
}

// Seed imports the current corpus, streaming, and reports the commit it came
// from.
//
// That commit is the resume point, so the seed and the first sweep cannot
// disagree — the source returns what it actually fetched rather than being told
// what to fetch. A tar rather than a zip because a zip's trailing index would
// force the whole corpus to disk before the first record decodes.
//
// Nothing is queued for triage; SeedStore is what enforces that.
func Seed(ctx context.Context, source CorpusSnapshot, target SeedStore, progress func(SeedResult)) (SeedResult, error) {
	stream, commit, committedAt, err := source.Snapshot(ctx)
	if err != nil {
		return SeedResult{}, fmt.Errorf("snapshot corpus: %w", err)
	}
	defer func() { _ = stream.Close() }()

	result, err := streamCorpus(ctx, stream, target, progress)
	result.Commit = commit
	result.CommittedAt = committedAt
	return result, err
}

// streamCorpus decodes records out of a tar as they arrive.
func streamCorpus(ctx context.Context, body io.Reader, target SeedStore, progress func(SeedResult)) (SeedResult, error) {
	result := SeedResult{}

	archive := tar.NewReader(body)
	batch := make([]cvefeed.Projection, 0, backfillBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := target.SaveCVERecords(ctx, batch); err != nil {
			// A whole batch failing is worth counting honestly rather than as
			// one failure: every record in it is unimported.
			result.Failed += len(batch)
		} else {
			result.Stored += len(batch)
		}
		batch = batch[:0]
		if progress != nil {
			progress(result)
		}
	}

	for {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("read corpus archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".json") {
			continue
		}
		if !cvefeed.ValidCVEID(strings.TrimSuffix(path.Base(header.Name), ".json")) {
			// delta.json, schemas, READMEs — the tree carries more than records.
			continue
		}
		result.Seen++

		// Capped: the published corpus contains a 23.4 MB record, and an
		// unbounded read here would size every buffer to the worst case.
		data, err := io.ReadAll(io.LimitReader(archive, cvefeed.MaxRecordBytes+1))
		if err != nil {
			result.Failed++
			continue
		}
		record, err := cvefeed.Decode(data)
		if err != nil {
			// One malformed record in 380,000 is a data problem to look at, not
			// a reason to abandon the import.
			result.Failed++
			continue
		}
		if record.Updated.After(result.Watermark) {
			result.Watermark = record.Updated
		}
		batch = append(batch, record)
		if len(batch) >= backfillBatchSize {
			flush()
		}
	}
	flush()
	return result, nil
}
