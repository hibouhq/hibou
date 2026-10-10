package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/storageusage"
	"github.com/hibouhq/hibou/internal/store"
)

// Storage usage sampler (ADR-039): one leader collects, every replica
// exports the persisted sample.

const storageUsageSampleKey = "storage_usage_sample"

func (s *Server) runStorageUsageLoop(ctx context.Context) {
	s.runStorageUsagePass(ctx)
	ticker := time.NewTicker(s.cfg.StorageUsage.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runStorageUsagePass(ctx)
		}
	}
}

func (s *Server) runStorageUsagePass(ctx context.Context) {
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockStorageUsage, s.collectStorageUsage)
	if err != nil {
		s.log.Error().Err(err).Msg("storage usage sample failed")
	} else if !ran {
		s.log.Debug().Msg("another replica is collecting storage usage")
	}
	// Followers and the leader alike serve what is persisted, so every
	// replica's /metrics agrees.
	sample, err := s.loadStorageUsageSample(ctx)
	if err != nil {
		s.log.Warn().Err(err).Msg("load storage usage sample")
		return
	}
	if sample != nil {
		storageusage.Default.Publish(sample)
	}
}

func (s *Server) collectStorageUsage(ctx context.Context) error {
	prev, err := s.loadStorageUsageSample(ctx)
	if err != nil {
		// A corrupt document only costs the carried-over inventory.
		s.log.Warn().Err(err).Msg("load previous storage usage sample")
	}
	sample := &storageusage.Sample{
		Postgres: storageusage.CollectPostgres(ctx, s.db, time.Now),
		Ledger:   storageusage.CollectLedger(ctx, s.db, time.Now),
	}
	sample.Backend = s.storageInventory(ctx, prev)
	for _, section := range []struct {
		source string
		err    string
	}{{"postgres", sample.Postgres.Error}, {"ledger", sample.Ledger.Error}} {
		if section.err != "" {
			s.log.Warn().Str("source", section.source).Str("error", section.err).Msg("storage usage source failed")
		}
	}
	encoded, err := json.Marshal(sample)
	if err != nil {
		return fmt.Errorf("encode storage usage sample: %w", err)
	}
	return s.queries.SetInstanceSettingValue(ctx, storageUsageSampleKey, encoded)
}

// storageInventory runs the opt-in backend inventory when it is due, and
// otherwise carries the previous result forward. Failures also wait a full
// interval, so a broken bucket is not listed every tick.
func (s *Server) storageInventory(ctx context.Context, prev *storageusage.Sample) *storageusage.Backend {
	cfg := s.cfg.StorageUsage.Inventory
	if !cfg.Enabled {
		return nil
	}
	inv, ok := s.objStore.(objstore.Inventorier)
	if !ok {
		return nil
	}
	if prev != nil && prev.Backend != nil && time.Since(prev.Backend.CollectedAt) < cfg.Interval {
		return prev.Backend
	}
	backend := storageusage.CollectBackend(ctx, inv, cfg.MaxObjects, time.Now)
	if backend.Error != "" {
		s.log.Warn().Str("error", backend.Error).Msg("artifact backend inventory failed")
	}
	return backend
}

func (s *Server) loadStorageUsageSample(ctx context.Context) (*storageusage.Sample, error) {
	raw, err := s.queries.GetInstanceSettingValue(ctx, storageUsageSampleKey)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	var sample storageusage.Sample
	if err := json.Unmarshal(raw, &sample); err != nil {
		return nil, fmt.Errorf("decode storage usage sample: %w", err)
	}
	return &sample, nil
}
