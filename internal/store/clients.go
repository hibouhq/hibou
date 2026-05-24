package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Client struct {
	ID                uuid.UUID       `json:"id"`
	OrgID             uuid.UUID       `json:"org_id"`
	Name              string          `json:"name"`
	Slug              string          `json:"slug"`
	Labels            json.RawMessage `json:"labels,omitempty"`
	ClientType        string          `json:"client_type"`
	ContactEmail      *string         `json:"contact_email,omitempty"`
	ContactName       *string         `json:"contact_name,omitempty"`
	NotificationPrefs json.RawMessage `json:"notification_prefs,omitempty"`
	Metadata          json.RawMessage `json:"metadata,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type ClientWithStats struct {
	Client
	DeploymentsCount int        `json:"deployments_count"`
	LastDeploymentAt *time.Time `json:"last_deployment_at,omitempty"`
	ActiveVersion    *string    `json:"active_version,omitempty"`
}

type ClientImpactVulnerability struct {
	CanonicalID    string `json:"canonical_id"`
	Severity       string `json:"severity"`
	ComponentName  string `json:"component_name"`
	ReleaseVersion string `json:"release_version"`
}

func (q *Queries) CreateClient(ctx context.Context, orgID uuid.UUID, name, slug string, labels json.RawMessage, clientType string, contactEmail, contactName *string, notificationPrefs, metadata json.RawMessage) (*Client, error) {
	row, err := q.db.CreateClient(ctx, dbgen.CreateClientParams{
		OrgID:             orgID,
		Name:              name,
		Slug:              slug,
		Labels:            defaultJSON(labels, []byte("{}")),
		ClientType:        clientType,
		ContactEmail:      nullStringFromPtr(contactEmail),
		ContactName:       nullStringFromPtr(contactName),
		NotificationPrefs: defaultJSON(notificationPrefs, []byte("{}")),
		Metadata:          defaultJSON(metadata, []byte("{}")),
	})
	if err != nil {
		return nil, err
	}

	return clientFromRow(row), nil
}

func (q *Queries) GetClientByID(ctx context.Context, id uuid.UUID) (*Client, error) {
	row, err := q.db.GetClientByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return clientFromRow(row), nil
}

func (q *Queries) GetClientBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*Client, error) {
	row, err := q.db.GetClientBySlug(ctx, dbgen.GetClientBySlugParams{OrgID: orgID, Slug: slug})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return clientFromRow(row), nil
}

func (q *Queries) ListClientsByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]Client, int, error) {
	rows, err := q.db.ListClientsByOrg(ctx, dbgen.ListClientsByOrgParams{OrgID: orgID, Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}

	clients := make([]Client, len(rows))
	for i, row := range rows {
		clients[i] = *clientFromRow(row)
	}

	total, err := q.db.CountClientsByOrg(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return clients, int(total), nil
}

func (q *Queries) ListClientsWithStatsByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]ClientWithStats, int, error) {
	rows, err := q.db.ListClientsWithStatsByOrg(ctx, dbgen.ListClientsWithStatsByOrgParams{OrgID: orgID, Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}

	clients := make([]ClientWithStats, len(rows))
	for i, row := range rows {
		clients[i] = ClientWithStats{
			Client: Client{
				ID:                row.ID,
				OrgID:             row.OrgID,
				Name:              row.Name,
				Slug:              row.Slug,
				Labels:            row.Labels,
				ClientType:        row.ClientType,
				ContactEmail:      stringPtrFromNull(row.ContactEmail),
				ContactName:       stringPtrFromNull(row.ContactName),
				NotificationPrefs: row.NotificationPrefs,
				Metadata:          row.Metadata,
				CreatedAt:         row.CreatedAt,
				UpdatedAt:         row.UpdatedAt,
			},
			DeploymentsCount: int(row.DeploymentsCount),
			LastDeploymentAt: timePtrFromValue(row.LastDeploymentAt),
			ActiveVersion:    stringPtrFromValue(row.ActiveVersion),
		}
	}

	total, err := q.db.CountClientsByOrg(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return clients, int(total), nil
}

func (q *Queries) ListClientImpactVulns(ctx context.Context, clientID uuid.UUID) ([]ClientImpactVulnerability, error) {
	rows, err := q.db.ListClientImpactVulns(ctx, clientID)
	if err != nil {
		return nil, err
	}

	vulns := make([]ClientImpactVulnerability, len(rows))
	for i, row := range rows {
		vulns[i] = ClientImpactVulnerability{
			CanonicalID:    row.CanonicalID,
			Severity:       row.Severity,
			ComponentName:  row.ComponentName,
			ReleaseVersion: row.ReleaseVersion,
		}
	}

	return vulns, nil
}

func (q *Queries) UpdateClient(ctx context.Context, id uuid.UUID, name string, labels json.RawMessage, clientType string, contactEmail, contactName *string, notificationPrefs, metadata json.RawMessage) (*Client, error) {
	row, err := q.db.UpdateClient(ctx, dbgen.UpdateClientParams{
		ID:                id,
		Name:              name,
		Labels:            defaultJSON(labels, []byte("{}")),
		ClientType:        clientType,
		ContactEmail:      nullStringFromPtr(contactEmail),
		ContactName:       nullStringFromPtr(contactName),
		NotificationPrefs: defaultJSON(notificationPrefs, []byte("{}")),
		Metadata:          defaultJSON(metadata, []byte("{}")),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return clientFromRow(row), nil
}

func (q *Queries) DeleteClient(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteClient(ctx, id)
}

func (q *Queries) ListClientLabelKeys(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	rows, err := q.db.ListClientLabelKeys(ctx, orgID)
	if err != nil {
		return nil, err
	}

	keys := make([]string, len(rows))
	copy(keys, rows)
	return keys, nil
}

func clientFromRow(row dbgen.Client) *Client {
	return &Client{
		ID:                row.ID,
		OrgID:             row.OrgID,
		Name:              row.Name,
		Slug:              row.Slug,
		Labels:            row.Labels,
		ClientType:        row.ClientType,
		ContactEmail:      stringPtrFromNull(row.ContactEmail),
		ContactName:       stringPtrFromNull(row.ContactName),
		NotificationPrefs: row.NotificationPrefs,
		Metadata:          row.Metadata,
		CreatedAt:         row.CreatedAt,
		UpdatedAt:         row.UpdatedAt,
	}
}

func timePtrFromValue(value interface{}) *time.Time {
	if value == nil {
		return nil
	}
	timestamp, ok := value.(time.Time)
	if !ok {
		return nil
	}
	return &timestamp
}

func stringPtrFromValue(value interface{}) *string {
	if value == nil {
		return nil
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return nil
	}
	return &text
}
