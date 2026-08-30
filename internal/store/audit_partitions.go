package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Two tables are range-partitioned by month: audit_logs (migration 00010,
// ADR-020) and advisory_events (migration 00031). The retention pass calls the
// maintainers daily under the leader lock: they create the current and next
// month's partitions ahead of writes and, when a hot-retention window is
// configured, expire old months with DROP TABLE instead of a bloating DELETE.
//
// Both migrations create only the first two monthly partitions, so without
// this pass every insert after that window lands in the default partition
// forever — which is precisely how advisory_events was found running.
type partitionedTable struct {
	// parent and defaultPartition are trusted identifiers baked in below, never
	// caller input — they are interpolated into DDL.
	parent           string
	defaultPartition string
	column           string
	pattern          *regexp.Regexp
}

var (
	auditLogsTable = partitionedTable{
		parent:           "audit_logs",
		defaultPartition: "audit_logs_default",
		column:           "created_at",
		pattern:          regexp.MustCompile(`^audit_logs_p(\d{6})$`),
	}
	// advisory_events partitions on occurred_at — the UPSTREAM event time, so a
	// backfilled event about an old CVE legitimately lands in the default
	// partition (no historical month exists for it). The maintainer only
	// guarantees the months new activity writes into.
	advisoryEventsTable = partitionedTable{
		parent:           "advisory_events",
		defaultPartition: "advisory_events_default",
		column:           "occurred_at",
		pattern:          regexp.MustCompile(`^advisory_events_p(\d{6})$`),
	}
)

func (t partitionedTable) partitionName(monthStart time.Time) string {
	return t.parent + "_p" + monthStart.Format("200601")
}

func monthStartUTC(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// partitionMonth parses a partition name back to its month start; ok is false
// for relations that are not maintenance-managed monthly partitions (the
// default partitions in particular), which must never be dropped.
func (t partitionedTable) partitionMonth(name string) (time.Time, bool) {
	match := t.pattern.FindStringSubmatch(name)
	if match == nil {
		return time.Time{}, false
	}
	parsed, err := time.Parse("200601", match[1])
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// retentionCutoff is the start of the oldest month kept. A partition is
// droppable only when its entire range is older than the cutoff.
func retentionCutoff(now time.Time, retentionMonths int) time.Time {
	return monthStartUTC(now).AddDate(0, -retentionMonths, 0)
}

func (q *Queries) MaintainAuditLogPartitions(ctx context.Context, now time.Time, retentionMonths int) error {
	return q.maintainPartitions(ctx, auditLogsTable, now, retentionMonths)
}

func (q *Queries) MaintainAdvisoryEventPartitions(ctx context.Context, now time.Time, retentionMonths int) error {
	return q.maintainPartitions(ctx, advisoryEventsTable, now, retentionMonths)
}

func (q *Queries) maintainPartitions(ctx context.Context, table partitionedTable, now time.Time, retentionMonths int) error {
	current := monthStartUTC(now)

	var errs []error
	for offset := 0; offset <= 1; offset++ {
		if err := q.ensurePartition(ctx, table, current.AddDate(0, offset, 0)); err != nil {
			errs = append(errs, err)
		}
	}

	if retentionMonths > 0 {
		if err := q.expirePartitions(ctx, table, retentionCutoff(now, retentionMonths)); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (q *Queries) ensurePartition(ctx context.Context, table partitionedTable, monthStart time.Time) error {
	name := table.partitionName(monthStart)
	from := monthStart.Format("2006-01-02")
	to := monthStart.AddDate(0, 1, 0).Format("2006-01-02")

	_, err := q.sqlDB.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
		name, table.parent, from, to,
	))
	if err == nil {
		return nil
	}

	// The plain CREATE fails when the default partition already holds rows for
	// this month (a replica was down across a month boundary). Move them: with
	// the default detached the CREATE is legal, and the re-routed INSERT puts
	// the strays where they belong. One transaction, so a failure changes
	// nothing and writes keep landing in default.
	tx, txErr := q.sqlDB.BeginTx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("create %s partition %s: %w", table.parent, name, errors.Join(err, txErr))
	}
	defer func() { _ = tx.Rollback() }()

	statements := []string{
		fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, table.parent, table.defaultPartition),
		fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`, name, table.parent, from, to),
		fmt.Sprintf(`INSERT INTO %s SELECT * FROM %s WHERE %s >= '%s' AND %s < '%s'`, name, table.defaultPartition, table.column, from, table.column, to),
		fmt.Sprintf(`DELETE FROM %s WHERE %s >= '%s' AND %s < '%s'`, table.defaultPartition, table.column, from, table.column, to),
		fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s DEFAULT`, table.parent, table.defaultPartition),
	}
	for _, statement := range statements {
		if _, execErr := tx.ExecContext(ctx, statement); execErr != nil {
			return fmt.Errorf("create %s partition %s: %w", table.parent, name, execErr)
		}
	}
	return tx.Commit()
}

func (q *Queries) expirePartitions(ctx context.Context, table partitionedTable, cutoff time.Time) error {
	rows, err := q.sqlDB.QueryContext(ctx, `
		SELECT c.relname
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class parent ON parent.oid = i.inhparent
		WHERE parent.relname = $1
	`, table.parent)
	if err != nil {
		return fmt.Errorf("list %s partitions: %w", table.parent, err)
	}
	defer func() { _ = rows.Close() }()

	var droppable []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan %s partition: %w", table.parent, err)
		}
		if monthStart, ok := table.partitionMonth(name); ok && !monthStart.AddDate(0, 1, 0).After(cutoff) {
			droppable = append(droppable, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list %s partitions: %w", table.parent, err)
	}

	var errs []error
	for _, name := range droppable {
		if _, err := q.sqlDB.ExecContext(ctx, `DROP TABLE IF EXISTS `+name); err != nil {
			errs = append(errs, fmt.Errorf("drop %s partition %s: %w", table.parent, name, err))
		}
	}

	// Pre-partitioning history and any strays live in the default partition,
	// where expiry is a plain DELETE.
	if _, err := q.sqlDB.ExecContext(ctx, fmt.Sprintf(
		`DELETE FROM %s WHERE %s < $1`, table.defaultPartition, table.column,
	), cutoff); err != nil {
		errs = append(errs, fmt.Errorf("expire default %s partition: %w", table.parent, err))
	}

	return errors.Join(errs...)
}
