package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/provider/depsdev"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// PackageSignal is one stored row of package_signals (ADR-048).
type PackageSignal = dbgen.PackageSignal

// UpsertPackageSignals writes a batch of normalized signals in one
// statement. An empty batch is a no-op.
func (q *Queries) UpsertPackageSignals(ctx context.Context, signals []depsdev.Signals) error {
	if len(signals) == 0 {
		return nil
	}
	params := dbgen.UpsertPackageSignalsParams{
		Purls:               make([]string, 0, len(signals)),
		Systems:             make([]string, 0, len(signals)),
		Names:               make([]string, 0, len(signals)),
		Versions:            make([]string, 0, len(signals)),
		PublishedAts:        make([]string, 0, len(signals)),
		CooldownEnds:        make([]string, 0, len(signals)),
		Deprecateds:         make([]bool, 0, len(signals)),
		DeprecatedReasons:   make([]string, 0, len(signals)),
		LowUsages:           make([]bool, 0, len(signals)),
		Alternatives:        make([]string, 0, len(signals)),
		NotFounds:           make([]bool, 0, len(signals)),
		Maliciouses:         make([]bool, 0, len(signals)),
		VulnerableCriticals: make([]bool, 0, len(signals)),
		RecommendedVersions: make([]string, 0, len(signals)),
		Raws:                make([]string, 0, len(signals)),
	}
	for _, s := range signals {
		alternatives, err := json.Marshal(nonNil(s.Alternatives))
		if err != nil {
			return fmt.Errorf("encode alternatives for %s: %w", s.Purl, err)
		}
		raw := "{}"
		if len(s.Raw) > 0 && json.Valid(s.Raw) {
			raw = string(s.Raw)
		}
		params.Purls = append(params.Purls, s.Purl)
		params.Systems = append(params.Systems, s.Key.System)
		params.Names = append(params.Names, s.Key.Name)
		params.Versions = append(params.Versions, s.Key.Version)
		params.PublishedAts = append(params.PublishedAts, formatOptionalTime(s.PublishedAt))
		params.CooldownEnds = append(params.CooldownEnds, formatOptionalTime(s.CooldownEnd))
		params.Deprecateds = append(params.Deprecateds, s.Deprecated)
		params.DeprecatedReasons = append(params.DeprecatedReasons, s.DeprecatedReason)
		params.LowUsages = append(params.LowUsages, s.LowUsage)
		params.Alternatives = append(params.Alternatives, string(alternatives))
		params.NotFounds = append(params.NotFounds, s.NotFound)
		params.Maliciouses = append(params.Maliciouses, s.Malicious)
		params.VulnerableCriticals = append(params.VulnerableCriticals, s.VulnerableCritical)
		params.RecommendedVersions = append(params.RecommendedVersions, s.RecommendedVersion)
		params.Raws = append(params.Raws, raw)
	}
	return q.db.UpsertPackageSignals(ctx, params)
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// GetPackageSignalsByPurls returns the stored rows keyed by purl. Purls
// without a row are absent: not evaluated.
func (q *Queries) GetPackageSignalsByPurls(ctx context.Context, purls []string) (map[string]PackageSignal, error) {
	out := make(map[string]PackageSignal, len(purls))
	if len(purls) == 0 {
		return out, nil
	}
	rows, err := q.db.GetPackageSignalsByPurls(ctx, purls)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.Purl] = row
	}
	return out, nil
}

// ListPackageSignalFreshness returns when each known purl was last fetched.
func (q *Queries) ListPackageSignalFreshness(ctx context.Context, purls []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(purls))
	if len(purls) == 0 {
		return out, nil
	}
	rows, err := q.db.ListPackageSignalFreshness(ctx, purls)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.Purl] = row.FetchedAt
	}
	return out, nil
}

// CountPackageSignals is the size of the local signal store.
func (q *Queries) CountPackageSignals(ctx context.Context) (int64, error) {
	count, err := q.db.CountPackageSignals(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return count, err
}

// PurgeAllPackageSignals removes every row; used when the provider is
// switched off so stale states do not linger.
func (q *Queries) PurgeAllPackageSignals(ctx context.Context) error {
	return q.db.PurgeAllPackageSignals(ctx)
}

// ListDistinctComponentPurlsBySnapshots is the candidate set for a sync
// chunk.
func (q *Queries) ListDistinctComponentPurlsBySnapshots(ctx context.Context, snapshotIDs []uuid.UUID) ([]string, error) {
	if len(snapshotIDs) == 0 {
		return []string{}, nil
	}
	return q.db.ListDistinctComponentPurlsBySnapshots(ctx, snapshotIDs)
}
