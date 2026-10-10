package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/epss"
	"github.com/hibouhq/hibou/internal/provider/rawratings"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Risk metrics upkeep (ADR-038): the ratings backfill, the CVE-feed
// reconcile and the EPSS mirror.

const (
	ratingsBatchSize = 500
	// ratingsReconcileInterval: the CVE feed sweeps every ~20 minutes; an
	// hour is soon enough for a rating to reach findings.
	ratingsReconcileInterval = time.Hour
	epssHealthKey            = "epss_last_sync"
)

var ratingsPassActive, epssSyncActive atomic.Bool

// runRatingsLoop rebuilds ratings stored by an older mapping once at start,
// then keeps CVE-feed ratings in step with the feed.
func (s *Server) runRatingsLoop(ctx context.Context) {
	s.runRatingsPass(ctx)
	ticker := time.NewTicker(ratingsReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runRatingsPass(ctx)
		}
	}
}

func (s *Server) runRatingsPass(ctx context.Context) {
	if !ratingsPassActive.CompareAndSwap(false, true) {
		return
	}
	defer ratingsPassActive.Store(false)
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockRatingsPass, func(runCtx context.Context) error {
		rebuilt, err := s.backfillRatings(runCtx)
		if err != nil {
			return err
		}
		reconciled, err := s.reconcileCVERatings(runCtx)
		if err != nil {
			return err
		}
		if rebuilt > 0 || reconciled > 0 {
			s.log.Info().Int("sources_rebuilt", rebuilt).Int("advisories_rerated", reconciled).Msg("ratings pass complete")
		}
		return nil
	})
	if err != nil {
		s.log.Error().Err(err).Msg("ratings pass failed")
	} else if !ran {
		s.log.Debug().Msg("another replica is running the ratings pass")
	}
}

// backfillRatings rebuilds the ratings of every source stored below
// advisory.RatingsVersion from its raw_data, then re-rates the advisories
// they belong to (ADR-038 §8). No provider is called.
func (s *Server) backfillRatings(ctx context.Context) (int, error) {
	total := 0
	for {
		sources, err := s.queries.ListAdvisorySourcesForRatings(ctx, dbgen.ListAdvisorySourcesForRatingsParams{
			RatingsVersion: advisory.RatingsVersion,
			BatchSize:      ratingsBatchSize,
		})
		if err != nil {
			return total, fmt.Errorf("list sources to rebuild: %w", err)
		}
		if len(sources) == 0 {
			return total, nil
		}
		advisories := make(map[uuid.UUID]struct{}, len(sources))
		for _, source := range sources {
			ratings, mapErr := rawratings.FromRaw(source.Provider, source.RawData)
			if mapErr != nil {
				// Unreadable raw data keeps no ratings rather than blocking
				// the backfill; the next provider refresh rewrites it.
				s.log.Warn().Err(mapErr).Str("provider", source.Provider).Str("provider_id", source.ProviderID).Msg("cannot rebuild ratings from stored record")
			}
			if err := s.inTx(ctx, func(q *store.Queries) error {
				if err := advisory.SyncSourceRatings(ctx, q, source.ID, ratings); err != nil {
					return err
				}
				return q.SetAdvisorySourceRatingsVersion(ctx, dbgen.SetAdvisorySourceRatingsVersionParams{
					ID: source.ID, RatingsVersion: advisory.RatingsVersion,
				})
			}); err != nil {
				return total, fmt.Errorf("rebuild ratings of %s/%s: %w", source.Provider, source.ProviderID, err)
			}
			advisories[source.AdvisoryID] = struct{}{}
			total++
		}
		for advisoryID := range advisories {
			if err := s.inTx(ctx, func(q *store.Queries) error {
				_, err := advisory.Rerate(ctx, q, advisoryID)
				return err
			}); err != nil {
				return total, fmt.Errorf("re-rate advisory %s: %w", advisoryID, err)
			}
		}
	}
}

// reconcileCVERatings re-rates advisories whose CVE-feed rating no longer
// matches the feed. Bounded: a pass handles at most 100 batches, the rest
// waits for the next tick.
func (s *Server) reconcileCVERatings(ctx context.Context) (int, error) {
	total := 0
	for range 100 {
		ids, err := s.queries.ListAdvisoriesWithStaleCVERating(ctx, ratingsBatchSize)
		if err != nil {
			return total, fmt.Errorf("list stale cve ratings: %w", err)
		}
		if len(ids) == 0 {
			return total, nil
		}
		for _, advisoryID := range ids {
			if err := s.inTx(ctx, func(q *store.Queries) error {
				_, err := advisory.Rerate(ctx, q, advisoryID)
				return err
			}); err != nil {
				return total, fmt.Errorf("re-rate advisory %s: %w", advisoryID, err)
			}
			total++
		}
	}
	return total, nil
}

func (s *Server) inTx(ctx context.Context, fn func(q *store.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// EPSSHealth is the stored summary of the last EPSS sync, same contract as
// KEV's: an empty mirror and a broken poller must not look alike.
type EPSSHealth struct {
	At           string `json:"at,omitempty"`
	ModelVersion string `json:"model_version,omitempty"`
	ScoreDate    string `json:"score_date,omitempty"`
	Rows         int    `json:"rows,omitempty"`
	Error        string `json:"error,omitempty"`
	FailingSince string `json:"failing_since,omitempty"`
}

// runEPSSSyncLoop mirrors FIRST's daily EPSS file (ADR-038 §4).
func (s *Server) runEPSSSyncLoop(ctx context.Context, url string, interval time.Duration) {
	s.runEPSSSync(ctx, url)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runEPSSSync(ctx, url)
		}
	}
}

func (s *Server) runEPSSSync(ctx context.Context, url string) {
	if !epssSyncActive.CompareAndSwap(false, true) {
		return
	}
	defer epssSyncActive.Store(false)
	_, err := store.WithLeaderLock(ctx, s.db, store.LockEPSSSync, func(runCtx context.Context) error {
		health := EPSSHealth{}
		if raw, err := s.queries.GetInstanceSettingValue(runCtx, epssHealthKey); err == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &health)
		}
		catalog, err := epss.Fetch(runCtx, nil, url)
		if err == nil && len(catalog.Scores) < epss.MinRows {
			err = fmt.Errorf("epss: file has %d rows, fewer than %d; keeping the current mirror", len(catalog.Scores), epss.MinRows)
		}
		var result store.EPSSReplaceResult
		if err == nil {
			result, err = s.queries.ReplaceEPSS(runCtx, s.db, catalog)
		}
		if err != nil {
			s.log.Error().Err(err).Msg("epss sync failed")
			health.Error = err.Error()
			if health.FailingSince == "" {
				health.FailingSince = time.Now().UTC().Format(time.RFC3339)
			}
		} else {
			health = EPSSHealth{
				At:           time.Now().UTC().Format(time.RFC3339),
				ModelVersion: catalog.ModelVersion,
				ScoreDate:    catalog.ScoreDate.Format("2006-01-02"),
				Rows:         len(catalog.Scores),
			}
			if result.Replaced {
				s.log.Info().Str("model_version", catalog.ModelVersion).Str("score_date", health.ScoreDate).Int("rows", result.Rows).Msg("epss mirror replaced")
			}
		}
		if encoded, marshalErr := json.Marshal(health); marshalErr == nil {
			if setErr := s.queries.SetInstanceSettingValue(runCtx, epssHealthKey, encoded); setErr != nil {
				s.log.Warn().Err(setErr).Msg("failed to record epss sync health")
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error().Err(err).Msg("epss sync pass failed")
	}
}
