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

type ForgeRepository struct {
	ID             uuid.UUID  `json:"id"`
	Provider       string     `json:"provider"`
	InstallationID *int64     `json:"installation_id,omitempty"`
	ProviderRepoID *string    `json:"provider_repo_id,omitempty"`
	AccountLogin   string     `json:"account_login"`
	Owner          string     `json:"owner"`
	Name           string     `json:"name"`
	FullName       string     `json:"full_name"`
	ProviderKey    string     `json:"provider_key"`
	Private        bool       `json:"private"`
	DefaultBranch  string     `json:"default_branch"`
	HTMLURL        string     `json:"html_url"`
	Archived       bool       `json:"archived"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	RemovedAt      *time.Time `json:"removed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type ForgeRepositoryUpsertResult struct {
	Repository        *ForgeRepository `json:"repository"`
	Inserted          bool             `json:"inserted"`
	PreviouslyRemoved bool             `json:"previously_removed"`
}

type ForgeRepositoryChange struct {
	ID          uuid.UUID `json:"id"`
	FullName    string    `json:"full_name"`
	ProviderKey string    `json:"provider_key"`
}

func (q *Queries) UpsertForgeRepository(ctx context.Context, repository ForgeRepository) (*ForgeRepositoryUpsertResult, error) {
	providerKey := normalizeForgeRepositoryKey(repository.FullName)
	row, err := q.db.UpsertForgeRepository(ctx, dbgen.UpsertForgeRepositoryParams{
		Provider:       strings.TrimSpace(repository.Provider),
		InstallationID: nullInt64FromPtr(repository.InstallationID),
		ProviderRepoID: nullStringFromPtr(repository.ProviderRepoID),
		AccountLogin:   strings.TrimSpace(repository.AccountLogin),
		Owner:          strings.TrimSpace(repository.Owner),
		Name:           strings.TrimSpace(repository.Name),
		FullName:       strings.TrimSpace(repository.FullName),
		ProviderKey:    providerKey,
		Private:        repository.Private,
		DefaultBranch:  strings.TrimSpace(repository.DefaultBranch),
		HtmlUrl:        strings.TrimSpace(repository.HTMLURL),
		Archived:       repository.Archived,
	})
	if err != nil {
		return nil, err
	}

	result := &ForgeRepository{
		ID:             row.ID,
		Provider:       row.Provider,
		InstallationID: int64PtrFromNull(row.InstallationID),
		ProviderRepoID: stringPtrFromNull(row.ProviderRepoID),
		AccountLogin:   row.AccountLogin,
		Owner:          row.Owner,
		Name:           row.Name,
		FullName:       row.FullName,
		ProviderKey:    providerKey,
		Private:        row.Private,
		DefaultBranch:  row.DefaultBranch,
		HTMLURL:        row.HtmlUrl,
		Archived:       row.Archived,
		LastSeenAt:     row.LastSeenAt,
		RemovedAt:      timePtrFromNull(row.RemovedAt),
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
	return &ForgeRepositoryUpsertResult{
		Repository:        result,
		Inserted:          row.Inserted,
		PreviouslyRemoved: row.PreviousRemovedAt.Valid,
	}, nil
}

func (q *Queries) SoftDeleteForgeRepository(ctx context.Context, provider, providerKey string) (*ForgeRepositoryChange, error) {
	rows, err := q.db.SoftDeleteForgeRepository(ctx, dbgen.SoftDeleteForgeRepositoryParams{
		Provider:    strings.TrimSpace(provider),
		ProviderKey: normalizeForgeRepositoryKey(providerKey),
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &ForgeRepositoryChange{
		ID:          rows[0].ID,
		FullName:    rows[0].FullName,
		ProviderKey: normalizeForgeRepositoryKey(rows[0].FullName),
	}, nil
}

func (q *Queries) MarkInstallationRepositoriesRemoved(ctx context.Context, provider string, installationID int64) ([]ForgeRepositoryChange, error) {
	rows, err := q.db.MarkInstallationRepositoriesRemoved(ctx, dbgen.MarkInstallationRepositoriesRemovedParams{
		Provider:       strings.TrimSpace(provider),
		InstallationID: sql.NullInt64{Int64: installationID, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	changes := make([]ForgeRepositoryChange, len(rows))
	for i, row := range rows {
		changes[i] = ForgeRepositoryChange{
			ID:          row.ID,
			FullName:    row.FullName,
			ProviderKey: row.ProviderKey,
		}
	}
	return changes, nil
}

func (q *Queries) SetForgeRepositoryArchived(ctx context.Context, provider, providerKey string, archived bool) (*ForgeRepositoryChange, error) {
	rows, err := q.db.SetForgeRepositoryArchived(ctx, dbgen.SetForgeRepositoryArchivedParams{
		Provider:    strings.TrimSpace(provider),
		ProviderKey: normalizeForgeRepositoryKey(providerKey),
		Archived:    archived,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &ForgeRepositoryChange{
		ID:          rows[0].ID,
		FullName:    rows[0].FullName,
		ProviderKey: normalizeForgeRepositoryKey(rows[0].FullName),
	}, nil
}

func (q *Queries) SetForgeRepositoryPrivate(ctx context.Context, provider, providerKey string, private bool) error {
	return q.db.SetForgeRepositoryPrivate(ctx, dbgen.SetForgeRepositoryPrivateParams{
		Provider:    strings.TrimSpace(provider),
		ProviderKey: normalizeForgeRepositoryKey(providerKey),
		Private:     private,
	})
}

func (q *Queries) ListForgeRepositoriesByAccount(ctx context.Context, provider, account string) ([]ForgeRepository, error) {
	rows, err := q.db.ListForgeRepositoriesByAccount(ctx, dbgen.ListForgeRepositoriesByAccountParams{
		Provider: strings.TrimSpace(provider),
		Lower:    strings.TrimSpace(account),
	})
	if err != nil {
		return nil, err
	}

	repositories := make([]ForgeRepository, len(rows))
	for i, row := range rows {
		repositories[i] = *forgeRepositoryFromRow(row)
	}

	return repositories, nil
}

func (q *Queries) GetForgeRepositoryByProviderRepoID(ctx context.Context, provider, providerRepoID string) (*ForgeRepository, error) {
	row, err := q.db.GetForgeRepositoryByProviderRepoID(ctx, dbgen.GetForgeRepositoryByProviderRepoIDParams{
		Provider:       strings.TrimSpace(provider),
		ProviderRepoID: nullString(strings.TrimSpace(providerRepoID)),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return forgeRepositoryFromRow(row), nil
}

func forgeRepositoryFromRow(row dbgen.ForgeRepository) *ForgeRepository {
	return &ForgeRepository{
		ID:             row.ID,
		Provider:       row.Provider,
		InstallationID: int64PtrFromNull(row.InstallationID),
		ProviderRepoID: stringPtrFromNull(row.ProviderRepoID),
		AccountLogin:   row.AccountLogin,
		Owner:          row.Owner,
		Name:           row.Name,
		FullName:       row.FullName,
		ProviderKey:    row.ProviderKey,
		Private:        row.Private,
		DefaultBranch:  row.DefaultBranch,
		HTMLURL:        row.HtmlUrl,
		Archived:       row.Archived,
		LastSeenAt:     row.LastSeenAt,
		RemovedAt:      timePtrFromNull(row.RemovedAt),
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func normalizeForgeRepositoryKey(fullName string) string {
	return strings.ToLower(strings.TrimSpace(fullName))
}

func int64PtrFromNull(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}

	result := value.Int64
	return &result
}

func nullInt64FromPtr(value *int64) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: *value, Valid: true}
}

func nullString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}
	}

	return sql.NullString{String: value, Valid: true}
}
