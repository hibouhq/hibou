package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type DeploymentStatus = dbgen.DeploymentStatus

const (
	DeploymentStatusActive     = dbgen.DeploymentStatusActive
	DeploymentStatusRolledBack = dbgen.DeploymentStatusRolledBack
	DeploymentStatusSuperseded = dbgen.DeploymentStatusSuperseded
)

type Deployment struct {
	ID               uuid.UUID        `json:"id"`
	ClientID         uuid.UUID        `json:"client_id"`
	ReleaseID        uuid.UUID        `json:"release_id"`
	Environment      string           `json:"environment"`
	Status           DeploymentStatus `json:"status"`
	DeployedAt       time.Time        `json:"deployed_at"`
	DeployedBy       *string          `json:"deployed_by,omitempty"`
	RollbackTargetID *uuid.UUID       `json:"rollback_target_id,omitempty"`
	Notes            *string          `json:"notes,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
}

type DeploymentWithRelease struct {
	Deployment
	ReleaseVersion *string `json:"release_version,omitempty"`
}

func (q *Queries) CreateDeployment(ctx context.Context, clientID, releaseID uuid.UUID, environment string, status DeploymentStatus, deployedAt time.Time, deployedBy *string, rollbackTargetID *uuid.UUID, notes *string) (*Deployment, error) {
	row, err := q.db.CreateDeployment(ctx, dbgen.CreateDeploymentParams{
		ClientID:         clientID,
		ReleaseID:        releaseID,
		Environment:      environment,
		Status:           status,
		DeployedAt:       deployedAt,
		DeployedBy:       nullStringFromPtr(deployedBy),
		RollbackTargetID: nullUUIDFromPtr(rollbackTargetID),
		Notes:            nullStringFromPtr(notes),
	})
	if err != nil {
		return nil, err
	}

	return deploymentFromRow(row), nil
}

func (q *Queries) GetDeploymentByID(ctx context.Context, id uuid.UUID) (*Deployment, error) {
	row, err := q.db.GetDeploymentByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return deploymentFromRow(row), nil
}

func (q *Queries) ListDeploymentsByClient(ctx context.Context, clientID uuid.UUID, limit, offset int) ([]Deployment, int, error) {
	rows, err := q.db.ListDeploymentsByClient(ctx, dbgen.ListDeploymentsByClientParams{ClientID: clientID, Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}

	deployments := make([]Deployment, len(rows))
	for i, row := range rows {
		deployments[i] = *deploymentFromRow(row)
	}

	total, err := q.db.CountDeploymentsByClient(ctx, clientID)
	if err != nil {
		return nil, 0, err
	}

	return deployments, int(total), nil
}

func (q *Queries) ListDeploymentsWithReleaseByClient(ctx context.Context, clientID uuid.UUID, limit, offset int) ([]DeploymentWithRelease, int, error) {
	rows, err := q.db.ListDeploymentsWithReleaseByClient(ctx, dbgen.ListDeploymentsWithReleaseByClientParams{ClientID: clientID, Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}

	deployments := make([]DeploymentWithRelease, len(rows))
	for i, row := range rows {
		deployments[i] = DeploymentWithRelease{
			Deployment: Deployment{
				ID:               row.ID,
				ClientID:         row.ClientID,
				ReleaseID:        row.ReleaseID,
				Environment:      row.Environment,
				Status:           row.Status,
				DeployedAt:       row.DeployedAt,
				DeployedBy:       stringPtrFromNull(row.DeployedBy),
				RollbackTargetID: uuidPtrFromNull(row.RollbackTargetID),
				Notes:            stringPtrFromNull(row.Notes),
				CreatedAt:        row.CreatedAt,
			},
			ReleaseVersion: stringPtrFromNull(row.ReleaseVersion),
		}
	}

	total, err := q.db.CountDeploymentsByClient(ctx, clientID)
	if err != nil {
		return nil, 0, err
	}

	return deployments, int(total), nil
}

func (q *Queries) ListDeploymentsByRelease(ctx context.Context, releaseID uuid.UUID, limit, offset int) ([]Deployment, int, error) {
	rows, err := q.db.ListDeploymentsByRelease(ctx, dbgen.ListDeploymentsByReleaseParams{ReleaseID: releaseID, Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}

	deployments := make([]Deployment, len(rows))
	for i, row := range rows {
		deployments[i] = *deploymentFromRow(row)
	}

	total, err := q.db.CountDeploymentsByRelease(ctx, releaseID)
	if err != nil {
		return nil, 0, err
	}

	return deployments, int(total), nil
}

func (q *Queries) UpdateDeploymentStatus(ctx context.Context, id uuid.UUID, status DeploymentStatus) (*Deployment, error) {
	row, err := q.db.UpdateDeploymentStatus(ctx, dbgen.UpdateDeploymentStatusParams{ID: id, Status: status})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return deploymentFromRow(row), nil
}

func (q *Queries) ListActiveDeploymentsByClient(ctx context.Context, clientID uuid.UUID) ([]Deployment, error) {
	rows, err := q.db.ListActiveDeploymentsByClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	deployments := make([]Deployment, len(rows))
	for i, row := range rows {
		deployments[i] = *deploymentFromRow(row)
	}

	return deployments, nil
}

func deploymentFromRow(row dbgen.Deployment) *Deployment {
	return &Deployment{
		ID:               row.ID,
		ClientID:         row.ClientID,
		ReleaseID:        row.ReleaseID,
		Environment:      row.Environment,
		Status:           row.Status,
		DeployedAt:       row.DeployedAt,
		DeployedBy:       stringPtrFromNull(row.DeployedBy),
		RollbackTargetID: uuidPtrFromNull(row.RollbackTargetID),
		Notes:            stringPtrFromNull(row.Notes),
		CreatedAt:        row.CreatedAt,
	}
}
