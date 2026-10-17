package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync/atomic"
	"time"

	"github.com/hibouhq/hibou/internal/provider/depsdev"
	"github.com/hibouhq/hibou/internal/store"
)

// Package signals (ADR-048): a daily pass looks up every public package
// version the instance depends on at deps.dev and stores cooldown,
// deprecation, low-usage, unpublished and recommended-version signals. The
// pass follows the KEV and EPSS loops: leader-locked, one health record an
// operator can read, and "disabled means disabled" (rows purged).

// signalsSnapshotChunk bounds one candidate query; signalsLookupChunk is
// well under the API's 5,000 limit so one slow chunk does not hold the
// pass for long.
const (
	signalsSnapshotChunk = 200
	signalsLookupChunk   = 1000
)

var packageSignalsActive atomic.Bool

func (s *Server) runPackageSignalsLoop(ctx context.Context) {
	s.runPackageSignalsPass(ctx)
	ticker := time.NewTicker(s.cfg.DepsDev.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runPackageSignalsPass(ctx)
		}
	}
}

func (s *Server) runPackageSignalsPass(ctx context.Context) {
	if !packageSignalsActive.CompareAndSwap(false, true) {
		return
	}
	defer packageSignalsActive.Store(false)
	_, err := store.WithLeaderLock(ctx, s.db, store.LockPackageSignals, s.packageSignalsPass)
	if err != nil {
		s.log.Error().Err(err).Msg("package signals pass failed")
	}
}

// purgePackageSignalsWhenDisabled clears stored rows once, so a switched-off
// provider does not keep showing cooldown and deprecation states nobody
// refreshes.
func (s *Server) purgePackageSignalsWhenDisabled(ctx context.Context) {
	_, err := store.WithLeaderLock(ctx, s.db, store.LockPackageSignals, func(runCtx context.Context) error {
		return s.queries.PurgeAllPackageSignals(runCtx)
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to purge package signals while the provider is disabled")
	}
}

func (s *Server) packageSignalsPass(ctx context.Context) error {
	started := time.Now()
	health := depsdev.Health{}
	if raw, err := s.queries.GetInstanceSettingValue(ctx, depsdev.HealthSettingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &health)
	}
	health.IntervalSeconds = int(s.cfg.DepsDev.Interval / time.Second)
	health.URL = s.cfg.DepsDev.URL
	if health.URL == "" {
		health.URL = depsdev.DefaultURL
	}

	stats, err := s.refreshPackageSignals(ctx)
	health.At = time.Now().UTC().Format(time.RFC3339)
	health.DurationMillis = time.Since(started).Milliseconds()
	health.Candidates = stats.candidates
	health.Private = stats.private
	health.Unsupported = stats.unsupported
	health.LookedUp = stats.lookedUp
	if count, countErr := s.queries.CountPackageSignals(ctx); countErr == nil {
		health.Stored = count
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		s.log.Error().Err(err).Int("looked_up", stats.lookedUp).Msg("package signals pass failed")
		health.Error = err.Error()
		if health.FailingSince == "" {
			health.FailingSince = health.At
		}
	} else {
		health.Error = ""
		health.FailingSince = ""
		health.SucceededAt = health.At
		s.log.Info().Int("candidates", stats.candidates).Int("looked_up", stats.lookedUp).Int("private", stats.private).Int("unsupported", stats.unsupported).Msg("package signals pass completed")
	}
	if encoded, marshalErr := json.Marshal(health); marshalErr == nil {
		if setErr := s.queries.SetInstanceSettingValue(ctx, depsdev.HealthSettingKey, encoded); setErr != nil {
			s.log.Warn().Err(setErr).Msg("failed to record package signals health")
		}
	}
	return nil
}

type packageSignalsStats struct {
	candidates  int
	private     int
	unsupported int
	lookedUp    int
}

// refreshPackageSignals collects every distinct purl in the snapshots the
// advisory pass scans, drops private and unsupported ones, and looks up
// those with no row or a row older than the interval.
func (s *Server) refreshPackageSignals(ctx context.Context) (packageSignalsStats, error) {
	stats := packageSignalsStats{}
	snapshotIDs, err := s.listLatestSnapshotsForAdvisoryScan(ctx)
	if err != nil {
		return stats, err
	}
	candidates := make(map[string]struct{})
	for start := 0; start < len(snapshotIDs); start += signalsSnapshotChunk {
		end := min(start+signalsSnapshotChunk, len(snapshotIDs))
		purls, err := s.queries.ListDistinctComponentPurlsBySnapshots(ctx, snapshotIDs[start:end])
		if err != nil {
			return stats, err
		}
		for _, purl := range purls {
			candidates[purl] = struct{}{}
		}
	}
	stats.candidates = len(candidates)

	type lookup struct {
		purl      string
		key       depsdev.VersionKey
		canonical string
	}
	lookups := make([]lookup, 0, len(candidates))
	for purl := range candidates {
		if depsdev.IsPrivate(purl, s.cfg.DepsDev.PrivateNamespaces) {
			stats.private++
			continue
		}
		key, canonical, ok := depsdev.ParsePurl(purl)
		if !ok {
			stats.unsupported++
			continue
		}
		lookups = append(lookups, lookup{purl: purl, key: key, canonical: canonical})
	}
	// Sorted by canonical purl so the spellings of one version (with or
	// without qualifiers, encoded or not) sit in the same chunk and share
	// one lookup.
	sort.Slice(lookups, func(i, j int) bool {
		if lookups[i].canonical == lookups[j].canonical {
			return lookups[i].purl < lookups[j].purl
		}
		return lookups[i].canonical < lookups[j].canonical
	})

	client := depsdev.New(s.cfg.DepsDev.URL, nil)
	cutoff := time.Now().Add(-s.cfg.DepsDev.Interval)
	for start := 0; start < len(lookups); start += signalsLookupChunk {
		end := min(start+signalsLookupChunk, len(lookups))
		chunk := lookups[start:end]
		purls := make([]string, 0, len(chunk))
		for _, item := range chunk {
			purls = append(purls, item.purl)
		}
		fresh, err := s.queries.ListPackageSignalFreshness(ctx, purls)
		if err != nil {
			return stats, err
		}
		// One API request per distinct version, however many purl spellings
		// or repositories carry it; every stale spelling gets a row.
		keys := make([]depsdev.VersionKey, 0, len(chunk))
		canonicals := make([]string, 0, len(chunk))
		pending := make([]lookup, 0, len(chunk))
		seen := make(map[string]struct{}, len(chunk))
		for _, item := range chunk {
			if fetchedAt, ok := fresh[item.purl]; ok && fetchedAt.After(cutoff) {
				continue
			}
			pending = append(pending, item)
			if _, dup := seen[item.canonical]; dup {
				continue
			}
			seen[item.canonical] = struct{}{}
			keys = append(keys, item.key)
			canonicals = append(canonicals, item.canonical)
		}
		if len(pending) == 0 {
			continue
		}
		findings, err := client.FindingsBatch(ctx, keys)
		if err != nil {
			return stats, err
		}
		infos, err := client.VersionBatch(ctx, canonicals)
		if err != nil {
			return stats, err
		}
		now := time.Now()
		signals := make([]depsdev.Signals, 0, len(pending))
		for _, item := range pending {
			var f *depsdev.FindingsResult
			if result, ok := findings[item.key]; ok {
				f = &result
			}
			info := infos[item.canonical]
			if f == nil && info == nil {
				// Neither endpoint answered: unknown, not a row.
				continue
			}
			signals = append(signals, depsdev.Normalize(item.purl, item.key, f, info, now))
		}
		if err := s.queries.UpsertPackageSignals(ctx, signals); err != nil {
			return stats, err
		}
		stats.lookedUp += len(signals)
	}
	return stats, nil
}

// packageSignalsFor returns stored signals for the given purls, or an empty
// map when the provider is off. Read paths must never call the API.
func (s *Server) packageSignalsFor(ctx context.Context, purls []string) map[string]store.PackageSignal {
	if !s.cfg.DepsDev.Enabled || s.queries == nil || len(purls) == 0 {
		return map[string]store.PackageSignal{}
	}
	signals, err := s.queries.GetPackageSignalsByPurls(ctx, purls)
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to load package signals")
		return map[string]store.PackageSignal{}
	}
	return signals
}

// attachPackageSignals adds the stored deps.dev signals of each
// component-backed finding's version (ADR-048 §8): cooldown, deprecation,
// unpublished, low usage, for the list's icons and the editor's diagnostic
// tags. Only stored rows are read; nothing is fetched here.
func (s *Server) attachPackageSignals(ctx context.Context, vulnerabilities []store.Vulnerability) {
	purls := make([]string, 0, len(vulnerabilities))
	seen := make(map[string]struct{}, len(vulnerabilities))
	for _, vuln := range vulnerabilities {
		if vuln.ComponentPurl == nil || *vuln.ComponentPurl == "" {
			continue
		}
		if _, dup := seen[*vuln.ComponentPurl]; dup {
			continue
		}
		seen[*vuln.ComponentPurl] = struct{}{}
		purls = append(purls, *vuln.ComponentPurl)
	}
	if len(purls) == 0 {
		return
	}
	rows := s.packageSignalsFor(ctx, purls)
	if len(rows) == 0 {
		return
	}
	now := time.Now()
	for i := range vulnerabilities {
		purl := vulnerabilities[i].ComponentPurl
		if purl == nil {
			continue
		}
		if row, ok := rows[*purl]; ok {
			vulnerabilities[i].Signals = componentSignalsFromRow(row, now)
		}
	}
}
