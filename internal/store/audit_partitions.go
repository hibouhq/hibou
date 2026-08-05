package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Audit logs are range-partitioned by month (migration 00010, ADR-020). The
// retention pass calls MaintainAuditLogPartitions daily under the leader lock:
// it creates the current and next month's partitions ahead of writes and, when
// a hot-retention window is configured, expires old months with DROP TABLE
// instead of a bloating DELETE.

var auditPartitionPattern = regexp.MustCompile(`^audit_logs_p(\d{6})$`)

func auditPartitionName(monthStart time.Time) string {
	return "audit_logs_p" + monthStart.Format("200601")
}

func monthStartUTC(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// auditPartitionMonth parses a partition name back to its month start; ok is
// false for relations that are not maintenance-managed monthly partitions
// (audit_logs_default in particular), which must never be dropped.
func auditPartitionMonth(name string) (time.Time, bool) {
	match := auditPartitionPattern.FindStringSubmatch(name)
	if match == nil {
		return time.Time{}, false
	}
	parsed, err := time.Parse("200601", match[1])
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// auditRetentionCutoff is the start of the oldest month kept. A partition is
// droppable only when its entire range is older than the cutoff.
func auditRetentionCutoff(now time.Time, retentionMonths int) time.Time {
	return monthStartUTC(now).AddDate(0, -retentionMonths, 0)
}

func (q *Queries) MaintainAuditLogPartitions(ctx context.Context, now time.Time, retentionMonths int) error {
	current := monthStartUTC(now)

	var errs []error
	for offset := 0; offset <= 1; offset++ {
		if err := q.ensureAuditPartition(ctx, current.AddDate(0, offset, 0)); err != nil {
			errs = append(errs, err)
		}
	}

	if retentionMonths > 0 {
		if err := q.expireAuditPartitions(ctx, auditRetentionCutoff(now, retentionMonths)); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (q *Queries) ensureAuditPartition(ctx context.Context, monthStart time.Time) error {
	name := auditPartitionName(monthStart)
	from := monthStart.Format("2006-01-02")
	to := monthStart.AddDate(0, 1, 0).Format("2006-01-02")

	_, err := q.sqlDB.ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_logs FOR VALUES FROM ('%s') TO ('%s')`,
		name, from, to,
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
		return fmt.Errorf("create audit partition %s: %w", name, errors.Join(err, txErr))
	}
	defer func() { _ = tx.Rollback() }()

	statements := []string{
		`ALTER TABLE audit_logs DETACH PARTITION audit_logs_default`,
		fmt.Sprintf(`CREATE TABLE %s PARTITION OF audit_logs FOR VALUES FROM ('%s') TO ('%s')`, name, from, to),
		fmt.Sprintf(`INSERT INTO %s SELECT * FROM audit_logs_default WHERE created_at >= '%s' AND created_at < '%s'`, name, from, to),
		fmt.Sprintf(`DELETE FROM audit_logs_default WHERE created_at >= '%s' AND created_at < '%s'`, from, to),
		`ALTER TABLE audit_logs ATTACH PARTITION audit_logs_default DEFAULT`,
	}
	for _, statement := range statements {
		if _, execErr := tx.ExecContext(ctx, statement); execErr != nil {
			return fmt.Errorf("create audit partition %s: %w", name, execErr)
		}
	}
	return tx.Commit()
}

func (q *Queries) expireAuditPartitions(ctx context.Context, cutoff time.Time) error {
	rows, err := q.sqlDB.QueryContext(ctx, `
		SELECT c.relname
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class parent ON parent.oid = i.inhparent
		WHERE parent.relname = 'audit_logs'
	`)
	if err != nil {
		return fmt.Errorf("list audit partitions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var droppable []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan audit partition: %w", err)
		}
		if monthStart, ok := auditPartitionMonth(name); ok && !monthStart.AddDate(0, 1, 0).After(cutoff) {
			droppable = append(droppable, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list audit partitions: %w", err)
	}

	var errs []error
	for _, name := range droppable {
		if _, err := q.sqlDB.ExecContext(ctx, `DROP TABLE IF EXISTS `+name); err != nil {
			errs = append(errs, fmt.Errorf("drop audit partition %s: %w", name, err))
		}
	}

	// Pre-partitioning history and any strays live in the default partition,
	// where expiry is a plain DELETE.
	if _, err := q.sqlDB.ExecContext(ctx,
		`DELETE FROM audit_logs_default WHERE created_at < $1`, cutoff,
	); err != nil {
		errs = append(errs, fmt.Errorf("expire default audit partition: %w", err))
	}

	return errors.Join(errs...)
}
