// Package storageusage measures how much storage a hibou instance uses —
// Postgres, the artifact ledger and, optionally, the artifact backend itself —
// and exports the latest measurement as Prometheus gauges (ADR-039).
//
// It measures usage only. Prices are joined outside hibou (OpenCost, FOCUS
// billing exports), so nothing here needs updating when a provider changes
// its rates.
package storageusage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hibouhq/hibou/internal/objstore"
)

const (
	// MaxTables caps the per-table series: the largest tables carry the
	// signal, and a bounded label set keeps the exporter cheap to scrape.
	MaxTables = 100
	// maxKinds caps the ledger's kind label; kinds are server-assigned, so
	// this is a guard, not a limit anyone should reach.
	maxKinds = 32
	// queryTimeout bounds every statement the sampler runs, so a lock or a
	// slow catalog never stalls the loop.
	queryTimeout = "10s"
)

// Sample is one measurement, persisted as a single JSON document so every
// replica exports the same values and an admin page can read it without a
// metrics stack.
type Sample struct {
	Postgres *Postgres `json:"postgres,omitempty"`
	Ledger   *Ledger   `json:"ledger,omitempty"`
	Backend  *Backend  `json:"backend,omitempty"`
}

// Section is the bookkeeping every source carries: a failed source keeps its
// timestamp and error so staleness and failure are both visible.
type Section struct {
	CollectedAt     time.Time `json:"collected_at"`
	DurationSeconds float64   `json:"duration_seconds"`
	Error           string    `json:"error,omitempty"`
}

// OK reports whether the section was collected without error.
func (s Section) OK() bool { return s.Error == "" }

// Postgres is the database-side measurement.
type Postgres struct {
	Section
	DatabaseBytes   int64        `json:"database_bytes"`
	Tables          []TableUsage `json:"tables"`
	ConnectionsUsed int64        `json:"connections_used"`
	ConnectionsMax  int64        `json:"connections_max"`
	XIDAge          int64        `json:"xid_age"`
	// OldestTransactionSeconds and CacheHitRatio are nil when the role cannot
	// see them or there is nothing to report; absent beats a faked zero.
	OldestTransactionSeconds *float64 `json:"oldest_transaction_seconds,omitempty"`
	CacheHitRatio            *float64 `json:"cache_hit_ratio,omitempty"`
}

// TableUsage is one public-schema table; a partitioned table is the sum of
// its leaf partitions.
type TableUsage struct {
	Name       string `json:"name"`
	TableBytes int64  `json:"table_bytes"`
	IndexBytes int64  `json:"index_bytes"`
	LiveRows   int64  `json:"live_rows"`
	DeadRows   int64  `json:"dead_rows"`
}

// Ledger is what hibou believes it stored, from snapshot_artifacts.
type Ledger struct {
	Section
	Kinds []KindUsage `json:"kinds"`
}

// KindUsage is the ledger total for one artifact kind.
type KindUsage struct {
	Kind    string `json:"kind"`
	Objects int64  `json:"objects"`
	Bytes   int64  `json:"bytes"`
}

// Backend is what the artifact backend actually holds.
type Backend struct {
	Section
	Objects   int64 `json:"objects"`
	Bytes     int64 `json:"bytes"`
	Truncated bool  `json:"truncated"`
	// Volume fields are set for the filesystem backend only.
	VolumeCapacityBytes *int64 `json:"volume_capacity_bytes,omitempty"`
	VolumeFreeBytes     *int64 `json:"volume_free_bytes,omitempty"`
}

// CollectPostgres measures the current database from catalog and statistics
// views. It needs no privilege beyond the application role.
func CollectPostgres(ctx context.Context, db *sql.DB, now func() time.Time) *Postgres {
	start := now()
	out := &Postgres{Section: Section{CollectedAt: start}}
	err := readOnly(ctx, db, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT pg_database_size(current_database())`).Scan(&out.DatabaseBytes); err != nil {
			return fmt.Errorf("database size: %w", err)
		}
		tables, err := tableUsage(ctx, tx)
		if err != nil {
			return err
		}
		out.Tables = tables
		if err := tx.QueryRowContext(ctx, `
			SELECT
				(SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'),
				current_setting('max_connections')::bigint,
				(SELECT age(datfrozenxid)::bigint FROM pg_database WHERE datname = current_database())`,
		).Scan(&out.ConnectionsUsed, &out.ConnectionsMax, &out.XIDAge); err != nil {
			return fmt.Errorf("connections and xid age: %w", err)
		}
		var oldest, hitRatio sql.NullFloat64
		if err := tx.QueryRowContext(ctx, `
			SELECT
				-- GREATEST: another backend's transaction can start after ours.
				(SELECT GREATEST(EXTRACT(EPOCH FROM now() - min(xact_start)), 0)::float8
				   FROM pg_stat_activity
				  WHERE datname = current_database() AND xact_start IS NOT NULL AND pid <> pg_backend_pid()),
				(SELECT blks_hit::float8 / NULLIF(blks_hit + blks_read, 0)
				   FROM pg_stat_database WHERE datname = current_database())`,
		).Scan(&oldest, &hitRatio); err != nil {
			return fmt.Errorf("transaction age and cache ratio: %w", err)
		}
		if oldest.Valid {
			out.OldestTransactionSeconds = &oldest.Float64
		}
		if hitRatio.Valid {
			out.CacheHitRatio = &hitRatio.Float64
		}
		return nil
	})
	finish(&out.Section, start, now, err)
	return out
}

// tableUsageQuery reports public-schema tables, folding partitions into their
// root so audit_logs is one series, not one per month.
const tableUsageQuery = `
WITH roots AS (
	SELECT c.oid, c.relname, c.relkind
	FROM pg_class c
	JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
), members AS (
	SELECT roots.relname, m.member
	FROM roots
	CROSS JOIN LATERAL (
		SELECT roots.oid WHERE roots.relkind = 'r'
		UNION ALL
		SELECT t.relid::oid FROM pg_partition_tree(roots.oid) t WHERE roots.relkind = 'p' AND t.isleaf
	) AS m(member)
)
SELECT relname, table_bytes, index_bytes, live_rows, dead_rows
FROM (
	SELECT members.relname,
		COALESCE(sum(pg_table_size(members.member)), 0)::bigint AS table_bytes,
		COALESCE(sum(pg_indexes_size(members.member)), 0)::bigint AS index_bytes,
		COALESCE(sum(s.n_live_tup), 0)::bigint AS live_rows,
		COALESCE(sum(s.n_dead_tup), 0)::bigint AS dead_rows
	FROM members
	LEFT JOIN pg_stat_user_tables s ON s.relid = members.member
	GROUP BY members.relname
) sized
ORDER BY table_bytes + index_bytes DESC, relname
LIMIT $1`

func tableUsage(ctx context.Context, tx *sql.Tx) ([]TableUsage, error) {
	rows, err := tx.QueryContext(ctx, tableUsageQuery, MaxTables)
	if err != nil {
		return nil, fmt.Errorf("table sizes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	tables := make([]TableUsage, 0, MaxTables)
	for rows.Next() {
		var t TableUsage
		if err := rows.Scan(&t.Name, &t.TableBytes, &t.IndexBytes, &t.LiveRows, &t.DeadRows); err != nil {
			return nil, fmt.Errorf("scan table size: %w", err)
		}
		tables = append(tables, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("table sizes: %w", err)
	}
	return tables, nil
}

// CollectLedger sums snapshot_artifacts per kind: what hibou believes it
// stored, for the cost of one aggregate and no backend call.
func CollectLedger(ctx context.Context, db *sql.DB, now func() time.Time) *Ledger {
	start := now()
	out := &Ledger{Section: Section{CollectedAt: start}, Kinds: []KindUsage{}}
	err := readOnly(ctx, db, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT kind, count(*), COALESCE(sum(size_bytes), 0)::bigint
			FROM snapshot_artifacts
			WHERE object_key <> ''
			GROUP BY kind
			ORDER BY kind
			LIMIT $1`, maxKinds)
		if err != nil {
			return fmt.Errorf("artifact ledger: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var k KindUsage
			if err := rows.Scan(&k.Kind, &k.Objects, &k.Bytes); err != nil {
				return fmt.Errorf("scan artifact ledger: %w", err)
			}
			out.Kinds = append(out.Kinds, k)
		}
		return rows.Err()
	})
	finish(&out.Section, start, now, err)
	return out
}

// readOnly runs fn in a READ ONLY transaction with a statement timeout, so the
// sampler can neither write nor hold the database hostage.
func readOnly(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin read-only transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout = '`+queryTimeout+`'`); err != nil {
		return fmt.Errorf("set statement timeout: %w", err)
	}
	return fn(tx)
}

func finish(s *Section, start time.Time, now func() time.Time, err error) {
	s.DurationSeconds = now().Sub(start).Seconds()
	if err != nil {
		s.Error = err.Error()
	}
}

// CollectBackend inventories the artifact backend. It is opt-in (ADR-039
// §2c): on S3 every 1,000 keys is a billed LIST request.
func CollectBackend(ctx context.Context, inv objstore.Inventorier, maxObjects int64, now func() time.Time) *Backend {
	start := now()
	out := &Backend{Section: Section{CollectedAt: start}}
	result, err := inv.Inventory(ctx, maxObjects)
	if err == nil {
		out.Objects = result.Objects
		out.Bytes = result.Bytes
		out.Truncated = result.Truncated
		if v := result.Volume; v != nil {
			out.VolumeCapacityBytes = &v.CapacityBytes
			out.VolumeFreeBytes = &v.FreeBytes
		}
	}
	finish(&out.Section, start, now, err)
	return out
}
