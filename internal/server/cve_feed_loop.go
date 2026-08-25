package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/cvetriage"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/provider/osv"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// feedRevisionKey is where the sweeper's cursor lives. It is a single value in
// instance_settings rather than a table of its own: there is exactly one feed.
const feedRevisionKey = "cve_feed_revision"

// autoApplyActorID attributes an auto-applied mapping to the mechanism rather
// than to a person who was not present for this particular advisory. The
// original decision keeps its own actor in the audit log.
var autoApplyActorID = uuid.MustParse("00000000-0000-0000-0000-000000000a11")

// feedHealthKey holds the last sweep's summary.
//
// It exists so "quiet week" and "broken poller" cannot look alike. An empty
// activity stream is ambiguous on its own; the same stream next to "last swept
// 8 minutes ago, 1,284 records seen, 0 matched" is not.
const feedHealthKey = "cve_feed_last_sweep"

// cveFeedDir is where the sweep keeps its blobless clone.
//
// Derived, not configured: the resume point lives in the database, so this is a
// pure cache — under 10 MB, seconds to rebuild. os.TempDir honours TMPDIR, which
// the chart points at a size-limited emptyDir; the root filesystem is read-only,
// and an unbounded clone in the container layer is how a node hits
// DiskPressure.
func cveFeedDir() string {
	return filepath.Join(os.TempDir(), "hibou-cvelist")
}

// FeedHealth is the stored summary of the most recent sweep.
type FeedHealth struct {
	At        string   `json:"at"`
	Revision  string   `json:"revision"`
	Seen      int      `json:"seen"`
	Stored    int      `json:"stored"`
	Queued    int      `json:"queued"`
	Revised   int      `json:"revised"`
	Withdrawn int      `json:"withdrawn"`
	Failed    int      `json:"failed"`
	QueuedIDs []string `json:"queued_ids"`

	// Error is the reason the most recent attempt failed, empty when it
	// succeeded. The success fields above are left in place when it is set, so
	// the reader sees both "last worked at X" and "failing since Y" — a feed
	// that stopped a week ago is otherwise indistinguishable from one that is
	// quiet because nothing changed.
	Error string `json:"error,omitempty"`
	// FailingSince is when the current run of failures started, not when the
	// latest one happened: the question a reader has is how long this has been
	// broken.
	FailingSince string `json:"failing_since,omitempty"`
}

var cveFeedSweepActive atomic.Bool

// runCVEFeedLoop sweeps the CVE feed on an interval.
//
// The cadence is a compromise the upstream sets for us: the CVE list commits
// roughly 2.8 times an hour, so polling much faster than that only costs
// requests. Fifteen minutes keeps a queue item's age honest without pretending
// to a freshness the source does not have.
func (s *Server) runCVEFeedLoop(ctx context.Context, sweeper *cvetriage.Sweeper, interval time.Duration) {
	if sweeper == nil || sweeper.Source == nil {
		return
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}

	s.runCVEFeedSweep(ctx, sweeper)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCVEFeedSweep(ctx, sweeper)
		}
	}
}

func (s *Server) runCVEFeedSweep(ctx context.Context, sweeper *cvetriage.Sweeper) {
	// In-process guard: a sweep that outruns its own tick would fetch the same
	// revision twice and race on the cursor.
	if !cveFeedSweepActive.CompareAndSwap(false, true) {
		s.log.Warn().Msg("cve feed sweep already running; skipping overlap")
		return
	}
	defer cveFeedSweepActive.Store(false)

	// Cross-replica guard. Unlike the advisory scan this is not only about
	// quota: every replica shares one git working copy per pod but one cursor
	// in the database, so concurrent sweeps would advance it past records a
	// different replica never stored.
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockCVEFeedSweep, func(runCtx context.Context) error {
		// Inside the lock so one replica seeds and the others find it done.
		if seedErr := s.seedCVECorpusIfEmpty(runCtx, sweeper); seedErr != nil {
			// Not fatal: an unseeded sweep still reports changes correctly, only
			// the preview is degraded.
			s.log.Warn().Err(seedErr).Msg("cve corpus seed failed; watch previews stay empty until it succeeds")
		}
		result, sweepErr := sweeper.Sweep(runCtx)
		if sweepErr != nil {
			return sweepErr
		}
		// One digest per pass, not one message per record. A well-targeted
		// subscription still bursts when a vendor publishes a batch, and a
		// channel that fires per record gets muted — which is indistinguishable
		// from having no queue at all.
		if result.Queued > 0 && s.bus != nil {
			s.bus.Publish(runCtx, events.Event{
				Type: events.TriageQueued,
				Payload: map[string]any{
					"identifiers": result.QueuedIDs,
					"severity":    "medium",
				},
				Timestamp: time.Now().UTC(),
			})
		}
		health := FeedHealth{
			At: time.Now().UTC().Format(time.RFC3339),
			// Success clears the failure fields by construction.
			Revision:  result.Revision,
			Seen:      result.Seen,
			Stored:    result.Stored,
			Queued:    result.Queued,
			Revised:   result.Revised,
			Withdrawn: result.Withdrawn,
			Failed:    result.Failed,
			QueuedIDs: result.QueuedIDs,
		}
		if encoded, marshalErr := json.Marshal(health); marshalErr == nil {
			if setErr := s.queries.SetInstanceSettingValue(runCtx, feedHealthKey, encoded); setErr != nil {
				s.log.Warn().Err(setErr).Msg("failed to record feed health")
			}
		}
		// A decision the world has moved past is worth re-opening in the same
		// pass that noticed the movement: waiting for a separate schedule means
		// a stale mapping keeps producing findings in the meantime.
		if review, reviewErr := cvetriage.Review(runCtx, &cveReviewStore{queries: s.queries}); reviewErr != nil {
			s.log.Warn().Err(reviewErr).Msg("advisory review pass failed")
		} else if review.Reopened > 0 || review.Withdrawn > 0 {
			s.log.Info().Int("reopened", review.Reopened).Int("withdrawn", review.Withdrawn).
				Msg("advisory review re-opened decisions the record moved past")
		}
		// Same pass: a superseded mapping keeps producing findings until
		// somebody notices, and that is not a mechanism.
		if divergence, divergenceErr := cvetriage.CheckDivergence(runCtx,
			&cveDivergenceStore{queries: s.queries}, s.upstreamCoordinates()); divergenceErr != nil {
			s.log.Warn().Err(divergenceErr).Msg("coordinate divergence check failed")
		} else if divergence.Superseded > 0 || divergence.Diverged > 0 {
			s.log.Info().
				Int("superseded", divergence.Superseded).
				Int("diverged", divergence.Diverged).
				Int("failed", divergence.Failed).
				Msg("upstream coordinates moved against mappings authored here")
		}
		// Every number, every pass. A sweep that saw a thousand records and
		// matched none is healthy; one that saw zero is a broken poller. Logging
		// only the interesting fields makes those two look identical.
		s.log.Info().
			Str("revision", result.Revision).
			Int("seen", result.Seen).
			Int("stored", result.Stored).
			Int("queued", result.Queued).
			Int("revised", result.Revised).
			Int("withdrawn", result.Withdrawn).
			Int("failed", result.Failed).
			Msg("cve feed sweep complete")
		return nil
	})
	if err != nil {
		s.log.Error().Err(err).Msg("cve feed sweep failed")
		s.recordCVEFeedFailure(ctx, err)
		return
	}
	if !ran {
		s.log.Debug().Msg("another replica is sweeping the cve feed; skipping this tick")
	}
}

// seedCVECorpusIfEmpty imports the corpus on the feed's first run.
//
// Without it every watch preview answers zero, including for correct product
// names — which looks like an answer. The commit is resolved first and used for
// both the snapshot and the resume point, so the two cannot disagree, and both
// come from the configured remote so a mirror works like any other.
func (s *Server) seedCVECorpusIfEmpty(ctx context.Context, sweeper *cvetriage.Sweeper) error {
	// Seeding needs a git remote to resolve the commit to snapshot, so it is the
	// git source or nothing. In production that is the only source there is; the
	// Not transport dispatch: this keeps a test's fake source off the network.
	source, canResolveCommit := sweeper.Source.(*cvefeed.GitSource)
	if !canResolveCommit {
		return nil
	}
	// Either marker means seeding is settled; re-seeding costs 380,000 records.
	state := &cveSweepStore{queries: s.queries, db: s.db}
	revision, err := state.FeedRevision(ctx)
	if err != nil {
		return fmt.Errorf("read feed revision: %w", err)
	}
	seed, err := state.FeedSeed(ctx)
	if err != nil {
		return fmt.Errorf("read feed seed: %w", err)
	}
	if revision != "" || seed.Commit != "" {
		return nil
	}

	s.log.Info().Msg("seeding CVE corpus; this runs once and takes about fifteen minutes")

	started := time.Now()
	result, err := cvetriage.Seed(ctx, source,
		&cveSeedStore{queries: s.queries, db: s.db},
		func(progress cvetriage.SeedResult) {
			s.log.Debug().Int("stored", progress.Stored).Msg("corpus seed progress")
		})
	if err != nil {
		return fmt.Errorf("seed corpus: %w", err)
	}

	encoded, err := json.Marshal(cvetriage.FeedSeed{
		Commit:      result.Commit,
		CommittedAt: result.CommittedAt,
	})
	if err != nil {
		return err
	}
	if err := s.queries.SetInstanceSettingValue(ctx, cvetriage.FeedSeedSettingKey, encoded); err != nil {
		return fmt.Errorf("record seed commit: %w", err)
	}
	s.log.Info().
		Str("commit", result.Commit).
		Time("committed_at", result.CommittedAt).
		Int("seen", result.Seen).
		Int("stored", result.Stored).
		Int("failed", result.Failed).
		Dur("took", time.Since(started)).
		Msg("CVE corpus seeded")
	return nil
}

// cveSeedStore is the seed's write path. It exposes nothing that can queue.
type cveSeedStore struct {
	queries *store.Queries
	db      *sql.DB
}

func (c *cveSeedStore) SaveCVERecords(ctx context.Context, records []cvefeed.Projection) error {
	return c.queries.SaveCVERecords(ctx, c.db, records)
}

// recordCVEFeedFailure makes a broken sweep visible where a working one is.
//
// Left to logs alone, a feed that has been failing since boot looks exactly like
// one with nothing to report.
func (s *Server) recordCVEFeedFailure(ctx context.Context, cause error) {
	if s.queries == nil {
		return
	}
	var health FeedHealth
	if raw, readErr := s.queries.GetInstanceSettingValue(ctx, feedHealthKey); readErr == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &health)
	}
	health.Error = cause.Error()
	if health.FailingSince == "" {
		// First failure of a run only: the question is how long it has been
		// broken, not when it was last retried.
		health.FailingSince = time.Now().UTC().Format(time.RFC3339)
	}
	encoded, marshalErr := json.Marshal(health)
	if marshalErr != nil {
		return
	}
	if setErr := s.queries.SetInstanceSettingValue(ctx, feedHealthKey, encoded); setErr != nil {
		s.log.Warn().Err(setErr).Msg("failed to record feed failure")
	}
}

// cveSweepStore adapts the store to the sweeper's needs.
type cveSweepStore struct {
	queries  *store.Queries
	db       *sql.DB
	ingester cvetriage.Ingester
	// autoApplyActor stands in for the person whose decision is being reused.
	// A synthetic id keeps Decision.Validate honest without pretending a human
	// was present for this particular advisory.
	autoApplyActor uuid.UUID
}

func (c *cveSweepStore) SaveCVERecord(ctx context.Context, record cvefeed.Projection) error {
	return c.queries.SaveCVERecord(ctx, c.db, record)
}

func (c *cveSweepStore) GetCVERecord(ctx context.Context, cveID string) (dbgen.CveRecord, error) {
	return c.queries.GetCVERecord(ctx, cveID)
}

// GetCVEAffected returns the stored affected products for a record.
func (c *cveSweepStore) GetCVEAffected(ctx context.Context, cveID string) ([]cvefeed.AffectedProduct, error) {
	rows, err := c.queries.ListCVEAffected(ctx, cveID)
	if err != nil {
		return nil, err
	}
	byProduct := map[string]int{}
	products := []cvefeed.AffectedProduct{}
	for _, row := range rows {
		index, seen := byProduct[row.ProductKey]
		if !seen {
			products = append(products, cvefeed.AffectedProduct{
				Vendor: row.Vendor, Product: row.Product,
				VendorKey: row.VendorKey, ProductKey: row.ProductKey,
			})
			index = len(products) - 1
			byProduct[row.ProductKey] = index
		}
		products[index].Ranges = append(products[index].Ranges, cvefeed.VersionRange{
			Introduced:   row.Introduced,
			Fixed:        row.Fixed,
			LastAffected: row.LastAffected,
		})
	}
	return products, nil
}

func (c *cveSweepStore) MatchSubscriptions(ctx context.Context, productKeys, vendorKeys []string) ([]dbgen.CveSubscription, error) {
	return c.queries.MatchSubscriptions(ctx, productKeys, vendorKeys)
}

func (c *cveSweepStore) QueueTriageItem(ctx context.Context, subscriptionID [16]byte, cveID string) error {
	return c.queries.QueueTriageItem(ctx, uuid.UUID(subscriptionID), cveID)
}

func (c *cveSweepStore) TouchSubscriptionMatched(ctx context.Context, subscriptionID [16]byte) error {
	return c.queries.TouchSubscriptionMatched(ctx, uuid.UUID(subscriptionID))
}

func (c *cveSweepStore) RecordAdvisoryEvent(ctx context.Context, event store.AdvisoryEvent) error {
	return c.queries.RecordAdvisoryEvent(ctx, event)
}

// FeedRevision reads the sweeper's cursor. A missing key means "never swept",
// which the sweeper treats as anchor-without-reporting rather than as a reason
// to queue the entire corpus.
// AutoApply returns a product's stored packages when its owner opted it in.
func (c *cveSweepStore) AutoApply(ctx context.Context, subscriptionID [16]byte) ([]cvetriage.Package, error) {
	mapping, err := c.queries.GetAutoApplyMapping(ctx, uuid.UUID(subscriptionID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	packages := []cvetriage.Package{}
	if err := json.Unmarshal(mapping.Packages, &packages); err != nil {
		// A stored mapping we cannot read is not a reason to fail the sweep,
		// and it must not silently apply either — fall through to the queue so
		// a person sees it.
		return nil, nil
	}
	return packages, nil
}

// ApplyMapping authors advisory data from a stored decision, attributed to
// whoever made that decision rather than to the sweep.
func (c *cveSweepStore) ApplyMapping(ctx context.Context, record cvefeed.Projection, packages []cvetriage.Package) error {
	if c.ingester == nil {
		return nil
	}
	_, err := cvetriage.Apply(ctx, c.ingester, cvetriage.Decision{
		CVEID:    record.ID,
		Packages: packages,
		ActorID:  c.autoApplyActor,
	}, record)
	return err
}

func (c *cveSweepStore) FeedRevision(ctx context.Context) (string, error) {
	raw, err := c.queries.GetInstanceSettingValue(ctx, feedRevisionKey)
	if err != nil || len(raw) == 0 {
		return "", err
	}
	var revision string
	if err := json.Unmarshal(raw, &revision); err != nil {
		// A corrupt cursor must not wedge ingestion: re-anchoring costs one
		// quiet pass, whereas returning an error here stalls the loop for ever.
		return "", nil
	}
	return revision, nil
}

// FeedSeed returns the commit the corpus was seeded from, and its date.
func (c *cveSweepStore) FeedSeed(ctx context.Context) (cvetriage.FeedSeed, error) {
	raw, err := c.queries.GetInstanceSettingValue(ctx, cvetriage.FeedSeedSettingKey)
	if err != nil || len(raw) == 0 {
		return cvetriage.FeedSeed{}, err
	}
	var seed cvetriage.FeedSeed
	if err := json.Unmarshal(raw, &seed); err != nil {
		// An unreadable record is one worth replacing, not one worth failing on.
		return cvetriage.FeedSeed{}, nil
	}
	return seed, nil
}

func (c *cveSweepStore) SetFeedRevision(ctx context.Context, revision string) error {
	encoded, err := json.Marshal(revision)
	if err != nil {
		return err
	}
	return c.queries.SetInstanceSettingValue(ctx, feedRevisionKey, encoded)
}

// cveDivergenceStore adapts the store to the divergence pass.
type cveDivergenceStore struct {
	queries *store.Queries
}

func (c *cveDivergenceStore) ListMappedCVEsForDivergenceCheck(ctx context.Context, limit int32) ([]dbgen.ListMappedCVEsForDivergenceCheckRow, error) {
	return c.queries.ListMappedCVEsForDivergenceCheck(ctx, limit)
}

func (c *cveDivergenceStore) RecordAdvisoryEvent(ctx context.Context, event store.AdvisoryEvent) error {
	return c.queries.RecordAdvisoryEvent(ctx, event)
}

// osvCoordinates asks OSV a narrower question than the scanner does: not "what
// affects this package" but "what packages does upstream name for this
// advisory".
type osvCoordinates struct {
	provider *osv.Provider
}

func (o *osvCoordinates) PackagesFor(ctx context.Context, cveID string) ([]cvetriage.Package, error) {
	coordinates, err := o.provider.PackagesForVuln(ctx, cveID)
	if err != nil {
		return nil, err
	}
	packages := make([]cvetriage.Package, 0, len(coordinates))
	for _, coordinate := range coordinates {
		packages = append(packages, cvetriage.Package{
			Ecosystem: coordinate.Ecosystem,
			Name:      coordinate.Name,
		})
	}
	return packages, nil
}

// upstreamCoordinates returns the database to compare authored mappings against.
//
// Built from the OSV URL, not the configured scan providers: coupling them would
// silently disable divergence on an instance that scans with Trivy alone.
func (s *Server) upstreamCoordinates() cvetriage.UpstreamCoordinates {
	return &osvCoordinates{provider: osv.New(s.cfg.OSVURL, s.log)}
}

// cveReviewStore adapts the store to the review pass.
type cveReviewStore struct {
	queries *store.Queries
}

func (c *cveReviewStore) ListTriageItemsNeedingReview(ctx context.Context) ([]dbgen.ListTriageItemsNeedingReviewRow, error) {
	return c.queries.ListTriageItemsNeedingReview(ctx)
}

func (c *cveReviewStore) ListWithdrawnMappedCVEs(ctx context.Context) ([]string, error) {
	return c.queries.ListWithdrawnMappedCVEs(ctx)
}

func (c *cveReviewStore) ReopenTriageItem(ctx context.Context, id [16]byte) error {
	return c.queries.ReopenTriageItem(ctx, uuid.UUID(id))
}

func (c *cveReviewStore) RecordAdvisoryEvent(ctx context.Context, event store.AdvisoryEvent) error {
	return c.queries.RecordAdvisoryEvent(ctx, event)
}
