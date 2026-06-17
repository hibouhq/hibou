package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type ForgeOrgAdmin struct {
	ID             uuid.UUID  `json:"id"`
	Provider       string     `json:"provider"`
	Account        string     `json:"account"`
	ProviderUserID string     `json:"provider_user_id"`
	OrgID          *uuid.UUID `json:"org_id,omitempty"`
	Granted        bool       `json:"granted"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (q *Queries) UpsertForgeOrgAdmin(ctx context.Context, provider, account, providerUserID string) (*ForgeOrgAdmin, error) {
	row, err := q.db.UpsertForgeOrgAdmin(ctx, dbgen.UpsertForgeOrgAdminParams{
		Provider:       strings.TrimSpace(provider),
		Account:        normalizeForgeOrgAdminAccount(account),
		ProviderUserID: strings.TrimSpace(providerUserID),
	})
	if err != nil {
		return nil, err
	}

	return forgeOrgAdminFromRow(row), nil
}

func (q *Queries) SetForgeOrgAdminOrg(ctx context.Context, provider, account, providerUserID string, orgID uuid.UUID) error {
	return q.db.SetForgeOrgAdminOrg(ctx, dbgen.SetForgeOrgAdminOrgParams{
		Provider:       strings.TrimSpace(provider),
		Account:        normalizeForgeOrgAdminAccount(account),
		ProviderUserID: strings.TrimSpace(providerUserID),
		OrgID:          uuid.NullUUID{UUID: orgID, Valid: orgID != uuid.Nil},
	})
}

func (q *Queries) MarkForgeOrgAdminGranted(ctx context.Context, id uuid.UUID) error {
	return q.db.MarkForgeOrgAdminGranted(ctx, id)
}

func (q *Queries) ListPendingForgeOrgAdminsByUser(ctx context.Context, provider, providerUserID string) ([]ForgeOrgAdmin, error) {
	rows, err := q.db.ListPendingForgeOrgAdminsByUser(ctx, dbgen.ListPendingForgeOrgAdminsByUserParams{
		Provider:       strings.TrimSpace(provider),
		ProviderUserID: strings.TrimSpace(providerUserID),
	})
	if err != nil {
		return nil, err
	}

	admins := make([]ForgeOrgAdmin, len(rows))
	for i, row := range rows {
		admins[i] = *forgeOrgAdminFromRow(row)
	}

	return admins, nil
}

func (q *Queries) ListForgeOrgAdminsByUser(ctx context.Context, provider, providerUserID string) ([]ForgeOrgAdmin, error) {
	rows, err := q.db.ListForgeOrgAdminsByUser(ctx, dbgen.ListForgeOrgAdminsByUserParams{
		Provider:       strings.TrimSpace(provider),
		ProviderUserID: strings.TrimSpace(providerUserID),
	})
	if err != nil {
		return nil, err
	}

	admins := make([]ForgeOrgAdmin, len(rows))
	for i, row := range rows {
		admins[i] = *forgeOrgAdminFromRow(row)
	}

	return admins, nil
}

func (q *Queries) GetForgeOrgAdmin(ctx context.Context, provider, account, providerUserID string) (*ForgeOrgAdmin, error) {
	row, err := q.db.GetForgeOrgAdmin(ctx, dbgen.GetForgeOrgAdminParams{
		Provider:       strings.TrimSpace(provider),
		Account:        normalizeForgeOrgAdminAccount(account),
		ProviderUserID: strings.TrimSpace(providerUserID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return forgeOrgAdminFromRow(row), nil
}

func (q *Queries) ForgeOrgAdminBindingExists(ctx context.Context, provider string, orgID uuid.UUID) (bool, error) {
	return q.db.ForgeOrgAdminBindingExists(ctx, dbgen.ForgeOrgAdminBindingExistsParams{
		Provider: strings.TrimSpace(provider),
		OrgID:    uuid.NullUUID{UUID: orgID, Valid: orgID != uuid.Nil},
	})
}

func forgeOrgAdminFromRow(row dbgen.ForgeOrgAdmin) *ForgeOrgAdmin {
	return &ForgeOrgAdmin{
		ID:             row.ID,
		Provider:       row.Provider,
		Account:        row.Account,
		ProviderUserID: row.ProviderUserID,
		OrgID:          uuidPtrFromNull(row.OrgID),
		Granted:        row.Granted,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func normalizeForgeOrgAdminAccount(account string) string {
	return strings.ToLower(strings.TrimSpace(account))
}
