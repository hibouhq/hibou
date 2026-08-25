package cvetriage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// SweepResult is what one pass over the feed did. Every field is reported
// rather than only the interesting ones: a pass that saw 1,300 records and
// matched none is healthy, while a pass that saw zero is a broken poller, and
// those must not look alike.
type SweepResult struct {
	Revision  string
	Seen      int
	Stored    int
	Matched   int
	Queued    int
	Withdrawn int
	Revised   int
	Applied   int
	Failed    int
	// QueuedIDs are the advisories this pass put in front of a person. Carried
	// so a notification can name them rather than only counting them.
	QueuedIDs []string
}

// SweepStore is the persistence the sweeper needs.
type SweepStore interface {
	SaveCVERecord(ctx context.Context, record cvefeed.Projection) error
	GetCVERecord(ctx context.Context, cveID string) (dbgen.CveRecord, error)
	// GetCVEAffected returns what we last stored for a record, so a revision can
	// say WHAT moved rather than only that something did.
	GetCVEAffected(ctx context.Context, cveID string) ([]cvefeed.AffectedProduct, error)
	MatchSubscriptions(ctx context.Context, productKeys, vendorKeys []string) ([]dbgen.CveSubscription, error)
	QueueTriageItem(ctx context.Context, subscriptionID [16]byte, cveID string) error
	TouchSubscriptionMatched(ctx context.Context, subscriptionID [16]byte) error
	RecordAdvisoryEvent(ctx context.Context, event store.AdvisoryEvent) error
	// AutoApply returns a subscription's stored packages when its owner has
	// opted that product into applying without a person, and nil otherwise.
	AutoApply(ctx context.Context, subscriptionID [16]byte) ([]Package, error)
	// ApplyMapping authors advisory data from a stored mapping.
	ApplyMapping(ctx context.Context, record cvefeed.Projection, packages []Package) error
	FeedRevision(ctx context.Context) (string, error)
	SetFeedRevision(ctx context.Context, revision string) error
	// FeedSeed is the commit the corpus was seeded from, zero when no seed has
	// run. Used only to resume a first sweep exactly — see
	// cvefeed.GitSource.SeedCommit.
	FeedSeed(ctx context.Context) (FeedSeed, error)
}

// FeedSeedSettingKey stores the commit the corpus was seeded from, and when that
// commit was made.
//
// The sweeper's first run starts from the current head without reporting, so a
// fresh install does not queue the whole corpus. Right on its own, wrong next to
// a seed: the seed is a snapshot of one commit, so everything between it and the
// first sweep would be in neither. This lets the first sweep resume from exactly
// where the seed stopped.
//
// Written by the corpus seed on first run, read by the sweep loop.
const FeedSeedSettingKey = "cve_feed_seed"

// FeedSeed is what that setting holds.
type FeedSeed struct {
	// Commit the corpus was snapshotted at, and where the first sweep resumes.
	Commit string `json:"commit"`
	// CommittedAt is when that commit was made upstream. It answers "how current
	// is this corpus", which the time the seed ran does not: a seed that finished
	// an hour ago from a week-old commit is a week behind.
	CommittedAt time.Time `json:"committed_at,omitempty"`
}

// Sweeper pulls changed records from the feed and turns them into queue items
// and timeline entries.
//
// It does not author anything. Matching a subscription queues a decision for a
// person; nothing here creates a finding, because the coordinate that would
// make a finding possible is exactly what no upstream record supplies.
type Sweeper struct {
	Source cvefeed.Source
	Store  SweepStore
	Log    zerolog.Logger
}

// Sweep runs one pass.
//
// The ordering matters on failure: the feed revision is advanced only after
// every changed record has been handled. A pass that dies halfway re-reads the
// same records next time — duplicate work, which is harmless because storing a
// record and queueing an item are both idempotent — rather than skipping them,
// which would lose an advisory silently.
func (s *Sweeper) Sweep(ctx context.Context) (SweepResult, error) {
	result := SweepResult{}

	previous, err := s.Store.FeedRevision(ctx)
	if err != nil {
		return result, fmt.Errorf("read feed revision: %w", err)
	}
	if source, ok := s.Source.(*cvefeed.GitSource); ok {
		source.Revision = previous
		if previous == "" {
			// No cursor yet. If an import has run, resume from the release it
			// left the data current to rather than from now, or the window
			// between the two is lost.
			if seed, seedErr := s.Store.FeedSeed(ctx); seedErr == nil {
				source.SeedCommit, source.SeedCommittedAt = seed.Commit, seed.CommittedAt
			}
		}
	}

	ids, revision, err := s.Source.Changed(ctx)
	if err != nil {
		return result, fmt.Errorf("read feed changes: %w", err)
	}
	result.Revision = revision
	result.Seen = len(ids)

	for _, cveID := range ids {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err := s.handle(ctx, cveID, &result); err != nil {
			// One malformed record must not stop the pass: the rest of the
			// batch is unrelated, and a record that fails twice is a data
			// problem to look at, not a reason to stall ingestion.
			result.Failed++
			s.Log.Warn().Err(err).Str("cve_id", cveID).Msg("skipping unreadable CVE record")
		}
	}

	// Advance only when every record in the batch landed. A failure here is
	// usually transient (the database blinked, one record was malformed), and
	// moving the cursor past it would skip those advisories for good — the
	// failure mode this whole feature exists to prevent. Re-reading them next
	// pass is free: storing a record and queueing an item are both idempotent.
	if result.Failed > 0 {
		s.Log.Warn().Int("failed", result.Failed).Str("revision", previous).
			Msg("holding feed revision so failed records are retried")
		return result, nil
	}
	if revision != "" && revision != previous {
		if err := s.Store.SetFeedRevision(ctx, revision); err != nil {
			return result, fmt.Errorf("advance feed revision: %w", err)
		}
	}
	return result, nil
}

func (s *Sweeper) handle(ctx context.Context, cveID string, result *SweepResult) error {
	raw, err := s.Source.Record(ctx, cveID)
	if err != nil {
		return err
	}
	record, err := cvefeed.Decode(raw)
	if err != nil {
		return err
	}

	// What did we know before? Absence is not an error — most records are new.
	previous, previousErr := s.Store.GetCVERecord(ctx, record.ID)
	hadRecord := previousErr == nil

	var priorAffected []cvefeed.AffectedProduct
	if hadRecord {
		// Read before the write overwrites it. Best-effort: losing the diff
		// costs detail on one timeline entry, not the sweep.
		priorAffected, _ = s.Store.GetCVEAffected(ctx, record.ID)
	}

	if err := s.Store.SaveCVERecord(ctx, record); err != nil {
		return err
	}
	result.Stored++

	switch {
	case hadRecord && previous.State != cvefeed.StateRejected && record.Withdrawn():
		// The transition with teeth: findings derived from this must retire.
		result.Withdrawn++
		s.emit(ctx, record, store.EventWithdrawn)
	case hadRecord && recordRevised(previous, record):
		result.Revised++
		// A revision that does not say what changed is not actionable: a
		// corrected typo and a bound that now covers versions somebody runs
		// look identical without the diff.
		s.emitRevision(ctx, record, priorAffected)
	case !hadRecord:
		s.emit(ctx, record, store.EventPublished)
	}

	// A withdrawn record is not queued for triage: there is nothing to decide.
	if record.Withdrawn() {
		return nil
	}

	productKeys, vendorKeys := recordKeys(record)
	if len(productKeys) == 0 {
		return nil
	}
	subscriptions, err := s.Store.MatchSubscriptions(ctx, productKeys, vendorKeys)
	if err != nil {
		return err
	}
	for _, subscription := range subscriptions {
		result.Matched++
		if err := s.Store.TouchSubscriptionMatched(ctx, subscription.ID); err != nil {
			return err
		}

		// A product whose owner has opted in skips the queue: the identity
		// question was already answered for this product, and asking it again
		// per CVE is the cost this whole feature exists to avoid paying twice.
		// Everything else still waits for a person.
		packages, err := s.Store.AutoApply(ctx, subscription.ID)
		if err != nil {
			return err
		}
		if len(packages) > 0 {
			if err := s.Store.ApplyMapping(ctx, record, packages); err != nil {
				return err
			}
			result.Applied++
			s.emit(ctx, record, store.EventAuthored)
			continue
		}

		if err := s.Store.QueueTriageItem(ctx, subscription.ID, record.ID); err != nil {
			return err
		}
		result.Queued++
	}
	if len(subscriptions) > 0 {
		result.QueuedIDs = append(result.QueuedIDs, record.ID)
	}
	return nil
}

func (s *Sweeper) emit(ctx context.Context, record cvefeed.Projection, kind store.AdvisoryEventKind) {
	occurredAt := record.Updated
	if occurredAt.IsZero() {
		occurredAt = record.Published
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	event := store.AdvisoryEvent{
		CVEID:      record.ID,
		Kind:       kind,
		OccurredAt: occurredAt,
	}
	if err := s.Store.RecordAdvisoryEvent(ctx, event); err != nil {
		// The timeline is a narrative, not a ledger the pass depends on. Losing
		// one entry is worth a log line, not a failed sweep.
		s.Log.Warn().Err(err).Str("cve_id", record.ID).Str("kind", string(kind)).
			Msg("failed to record advisory event")
	}
}

// recordRevised reports whether the CNA moved the record since we stored it.
func recordRevised(previous dbgen.CveRecord, record cvefeed.Projection) bool {
	if !previous.RecordUpdatedAt.Valid || record.Updated.IsZero() {
		return false
	}
	return record.Updated.After(previous.RecordUpdatedAt.Time)
}

// recordKeys collects the normalized names a record could be watched under.
func recordKeys(record cvefeed.Projection) (productKeys, vendorKeys []string) {
	productSeen, vendorSeen := map[string]struct{}{}, map[string]struct{}{}
	for _, product := range record.Affected {
		if _, ok := productSeen[product.ProductKey]; !ok && product.ProductKey != "" {
			productSeen[product.ProductKey] = struct{}{}
			productKeys = append(productKeys, product.ProductKey)
		}
		if _, ok := vendorSeen[product.VendorKey]; !ok && product.VendorKey != "" {
			vendorSeen[product.VendorKey] = struct{}{}
			vendorKeys = append(vendorKeys, product.VendorKey)
		}
	}
	return productKeys, vendorKeys
}

// ErrNoSource is returned when a sweeper is started without a feed.
var ErrNoSource = errors.New("cvetriage: sweeper has no source")

// emitRevision records a CNA revision along with the ranges that moved.
func (s *Sweeper) emitRevision(ctx context.Context, record cvefeed.Projection, prior []cvefeed.AffectedProduct) {
	deltas := DiffRanges(cvefeed.Projection{ID: record.ID, Affected: prior}, record)
	detail := json.RawMessage(`{}`)
	if len(deltas) > 0 {
		if encoded, err := json.Marshal(map[string]any{"ranges": deltas}); err == nil {
			detail = encoded
		}
	}
	occurredAt := record.Updated
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	if err := s.Store.RecordAdvisoryEvent(ctx, store.AdvisoryEvent{
		CVEID:      record.ID,
		Kind:       store.EventCNARevised,
		OccurredAt: occurredAt,
		Detail:     detail,
	}); err != nil {
		s.Log.Warn().Err(err).Str("cve_id", record.ID).Msg("failed to record a revision event")
	}
}
