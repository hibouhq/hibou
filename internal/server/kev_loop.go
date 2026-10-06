package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store"
)

// kevHealthKey holds the last KEV sync's summary, same contract as the CVE
// feed's: an empty catalog and a broken poller must never look alike. One
// entry per source — "CISA synced an hour ago, EUVD failing since Tuesday" is
// the actual state, and a single merged status would hide exactly the half
// that is broken.
const kevHealthKey = "kev_last_sync"

// KEVHealth is the stored summary of the most recent sync pass.
type KEVHealth struct {
	// At is when the loop last completed a pass (whether or not every source
	// succeeded); staleness is judged against the configured interval.
	At      string            `json:"at"`
	Sources []KEVSourceHealth `json:"sources"`
	// IntervalSeconds is the configured sync cadence, carried so the UI can
	// judge staleness against the actual schedule instead of a guess.
	IntervalSeconds int `json:"interval_seconds,omitempty"`
}

// KEVSourceHealth is one catalog's sync state.
type KEVSourceHealth struct {
	Source string `json:"source"`
	// At is this source's last SUCCESSFUL sync. It stays in place when Error
	// is set, so a reader sees both "last worked at X" and "failing since Y".
	At             string `json:"at,omitempty"`
	CatalogVersion string `json:"catalog_version,omitempty"`
	Released       string `json:"released,omitempty"`
	Entries        int    `json:"entries,omitempty"`
	// Skipped counts upstream entries dropped for not carrying a usable CVE id.
	Skipped int `json:"skipped,omitempty"`

	Error        string `json:"error,omitempty"`
	FailingSince string `json:"failing_since,omitempty"`
}

var kevSyncActive atomic.Bool

// runKEVSyncLoop refreshes the local exploited-catalog mirrors on an interval.
func (s *Server) runKEVSyncLoop(ctx context.Context, sources []kev.Source, interval time.Duration) {
	if len(sources) == 0 {
		return
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	s.runKEVSync(ctx, sources, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runKEVSync(ctx, sources, interval)
		}
	}
}

func (s *Server) runKEVSync(ctx context.Context, sources []kev.Source, interval time.Duration) {
	// In-process guard, same reason as the CVE feed: a sync outrunning its own
	// tick would replace the same rows twice for one catalog.
	if !kevSyncActive.CompareAndSwap(false, true) {
		s.log.Warn().Msg("kev sync already running; skipping overlap")
		return
	}
	defer kevSyncActive.Store(false)

	// Cross-replica guard: N replicas each downloading and replacing the same
	// catalogs is pure waste; the result is identical.
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockKEVSync, func(runCtx context.Context) error {
		// A source the operator disabled must stop gating AND stop reporting:
		// its rows are a frozen catalog nobody refreshes, and its old health
		// entry would show "failing" forever. Both are scoped to the active
		// set, so this also cleans up after a renamed or removed source.
		activeNames := make([]string, 0, len(sources))
		for _, source := range sources {
			activeNames = append(activeNames, source.Name())
		}
		if purgeErr := s.queries.PurgeKEVSourcesExcept(runCtx, activeNames); purgeErr != nil {
			return fmt.Errorf("purge disabled kev sources: %w", purgeErr)
		}
		health := s.loadKEVHealth(runCtx)
		health.pruneTo(activeNames)
		health.IntervalSeconds = int(interval / time.Second)
		// One source failing must not stop the others: CISA being down is no
		// reason to serve a stale EUVD, and vice versa.
		for _, source := range sources {
			entry := health.source(source.Name())
			catalog, fetchErr := source.Fetch(runCtx)
			if fetchErr == nil {
				fetchErr = s.queries.ReplaceKEVSource(runCtx, s.db, source.Name(), catalog.Entries, source.WithdrawalGrace())
			}
			if fetchErr != nil {
				s.log.Error().Err(fetchErr).Str("source", source.Name()).Msg("kev catalog sync failed")
				entry.Error = fetchErr.Error()
				if entry.FailingSince == "" {
					entry.FailingSince = time.Now().UTC().Format(time.RFC3339)
				}
				continue
			}
			// Success clears the failure fields by construction.
			*entry = KEVSourceHealth{
				Source:         source.Name(),
				At:             time.Now().UTC().Format(time.RFC3339),
				CatalogVersion: catalog.Version,
				Released:       catalog.Released,
				Entries:        len(catalog.Entries),
				Skipped:        catalog.Skipped,
			}
			s.log.Info().
				Str("source", source.Name()).
				Str("catalog_version", catalog.Version).
				Int("entries", len(catalog.Entries)).
				Int("skipped", catalog.Skipped).
				Msg("kev catalog sync complete")
		}
		health.At = time.Now().UTC().Format(time.RFC3339)
		if encoded, marshalErr := json.Marshal(health); marshalErr == nil {
			if setErr := s.queries.SetInstanceSettingValue(runCtx, kevHealthKey, encoded); setErr != nil {
				s.log.Warn().Err(setErr).Msg("failed to record kev sync health")
			}
		}
		return nil
	})
	if err != nil {
		// Only the lock/connection path lands here; per-source failures are
		// recorded above without failing the pass.
		s.log.Error().Err(err).Msg("kev sync pass failed")
		return
	}
	if !ran {
		s.log.Debug().Msg("another replica is syncing the kev catalogs; skipping this tick")
	}
}

// purgeKEVWhenDisabled clears the mirror once at startup when no KEV source is
// configured to sync. Without it, disabling the sync would freeze whatever the
// table held — including entries the publishers have since withdrawn — and the
// gate would keep blocking on it with no withdrawal path.
func (s *Server) purgeKEVWhenDisabled(ctx context.Context) {
	_, err := store.WithLeaderLock(ctx, s.db, store.LockKEVSync, func(runCtx context.Context) error {
		return s.queries.PurgeAllKEVEntries(runCtx)
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to purge kev entries while the sync is disabled; stored entries keep gating until this succeeds")
	}
}

// loadKEVHealth reads the stored health so one source's failure record
// survives another source's success. A missing or unreadable value starts
// fresh — it is a summary, not a ledger.
func (s *Server) loadKEVHealth(ctx context.Context) *KEVHealth {
	health := &KEVHealth{}
	if raw, err := s.queries.GetInstanceSettingValue(ctx, kevHealthKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, health)
	}
	return health
}

// pruneTo drops health entries for sources no longer in the active set.
func (h *KEVHealth) pruneTo(active []string) {
	keep := make(map[string]struct{}, len(active))
	for _, name := range active {
		keep[name] = struct{}{}
	}
	pruned := h.Sources[:0]
	for _, source := range h.Sources {
		if _, ok := keep[source.Source]; ok {
			pruned = append(pruned, source)
		}
	}
	h.Sources = pruned
}

// source returns the health entry for a source, appending one if absent.
func (h *KEVHealth) source(name string) *KEVSourceHealth {
	for i := range h.Sources {
		if h.Sources[i].Source == name {
			return &h.Sources[i]
		}
	}
	h.Sources = append(h.Sources, KEVSourceHealth{Source: name})
	return &h.Sources[len(h.Sources)-1]
}
