package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

func (q *Queries) SetManagedMaintenanceSettings(ctx context.Context, org uuid.UUID, settings json.RawMessage) error {
	_, err := q.sqlDB.ExecContext(ctx, `UPDATE organizations SET settings=jsonb_set(COALESCE(settings,'{}'),'{managed_remediation_targets}',$2::jsonb) WHERE id=$1`, org, settings)
	return err
}

func (q *Queries) HasManagedMaintenanceIntent(ctx context.Context, org uuid.UUID, resource string) (bool, error) {
	var exists bool
	err := q.sqlDB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs WHERE org_id=$1 AND resource_type='remediation_maintenance_target'
	AND resource_id=$2 AND action='remediation.maintenance.intent')`, org, resource).Scan(&exists)
	return exists, err
}

func (q *Queries) WithManagedMaintenanceLock(ctx context.Context, repo uuid.UUID, target string, fn func() error) error {
	tx, err := q.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, repo.String()+"/"+target); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return tx.Commit()
}
