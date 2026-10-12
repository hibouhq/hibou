package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type Organization struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Provider    string          `json:"provider"`
	Settings    json.RawMessage `json:"settings"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	// ForgeAccountID is the immutable forge-side id of the account this org
	// was provisioned for; ForgeAccountLogin its last verified login. Both are
	// empty for legacy and manually created orgs, which fall back to the slug.
	ForgeAccountID    string `json:"-"`
	ForgeAccountLogin string `json:"-"`
}

func (q *Queries) CreateOrganization(ctx context.Context, name, slug, displayName, provider string) (*Organization, error) {
	row, err := q.db.CreateOrganization(ctx, dbgen.CreateOrganizationParams{
		Name:        name,
		Slug:        slug,
		DisplayName: displayName,
		Provider:    provider,
	})
	if err != nil {
		return nil, err
	}

	return orgFromFields(row.ID, row.Name, row.Slug, row.DisplayName, row.Provider, row.Settings, row.CreatedAt, row.UpdatedAt).withForgeAccount(row.ForgeAccountID, row.ForgeAccountLogin), nil
}

func (q *Queries) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	row, err := q.db.GetOrganizationByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromFields(row.ID, row.Name, row.Slug, row.DisplayName, row.Provider, row.Settings, row.CreatedAt, row.UpdatedAt).withForgeAccount(row.ForgeAccountID, row.ForgeAccountLogin), nil
}

func (q *Queries) GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*Organization, error) {
	row, err := q.db.GetOrganizationByProviderAndSlug(ctx, dbgen.GetOrganizationByProviderAndSlugParams{
		Provider: provider,
		Slug:     slug,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromFields(row.ID, row.Name, row.Slug, row.DisplayName, row.Provider, row.Settings, row.CreatedAt, row.UpdatedAt).withForgeAccount(row.ForgeAccountID, row.ForgeAccountLogin), nil
}

func (q *Queries) ListOrganizationsByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]Organization, int, error) {
	rows, err := q.db.ListOrganizationsByUser(ctx, dbgen.ListOrganizationsByUserParams{
		UserID: userID,
		Limit:  int32(limit),  // #nosec G115 -- pagination values are bounded by API parsing.
		Offset: int32(offset), // #nosec G115 -- pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	organizations := make([]Organization, len(rows))
	for i, row := range rows {
		organizations[i] = Organization{
			ID:          row.ID,
			Name:        row.Name,
			Slug:        row.Slug,
			DisplayName: row.DisplayName,
			Provider:    row.Provider,
			Settings:    row.Settings,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,

			ForgeAccountID:    row.ForgeAccountID.String,
			ForgeAccountLogin: row.ForgeAccountLogin.String,
		}
	}

	total, err := q.db.CountOrganizationsByUser(ctx, userID)
	if err != nil {
		return nil, 0, err
	}

	return organizations, int(total), nil
}

func (q *Queries) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := q.db.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	organizations := make([]Organization, len(rows))
	for i, row := range rows {
		organizations[i] = Organization{
			ID:          row.ID,
			Name:        row.Name,
			Slug:        row.Slug,
			DisplayName: row.DisplayName,
			Provider:    row.Provider,
			Settings:    row.Settings,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,

			ForgeAccountID:    row.ForgeAccountID.String,
			ForgeAccountLogin: row.ForgeAccountLogin.String,
		}
	}
	return organizations, nil
}

func (q *Queries) UpdateOrganization(ctx context.Context, id uuid.UUID, name, displayName string) (*Organization, error) {
	row, err := q.db.UpdateOrganization(ctx, dbgen.UpdateOrganizationParams{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromFields(row.ID, row.Name, row.Slug, row.DisplayName, row.Provider, row.Settings, row.CreatedAt, row.UpdatedAt).withForgeAccount(row.ForgeAccountID, row.ForgeAccountLogin), nil
}

func (q *Queries) UpdateOrganizationSettings(ctx context.Context, id uuid.UUID, settings json.RawMessage) (*Organization, error) {
	row, err := q.db.UpdateOrganizationSettings(ctx, dbgen.UpdateOrganizationSettingsParams{
		ID:       id,
		Settings: settings,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromFields(row.ID, row.Name, row.Slug, row.DisplayName, row.Provider, row.Settings, row.CreatedAt, row.UpdatedAt).withForgeAccount(row.ForgeAccountID, row.ForgeAccountLogin), nil
}

func (q *Queries) DeleteOrganization(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteOrganization(ctx, id)
}

func orgFromFields(id uuid.UUID, name, slug, displayName, provider string, settings json.RawMessage, createdAt, updatedAt time.Time) *Organization {
	return &Organization{
		ID:          id,
		Name:        name,
		Slug:        slug,
		DisplayName: displayName,
		Provider:    provider,
		Settings:    settings,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func (o *Organization) withForgeAccount(id, login sql.NullString) *Organization {
	o.ForgeAccountID = id.String
	o.ForgeAccountLogin = login.String
	return o
}

func (q *Queries) GetOrganizationByForgeAccountID(ctx context.Context, provider, accountID string) (*Organization, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, nil
	}
	row, err := q.db.GetOrganizationByForgeAccountID(ctx, dbgen.GetOrganizationByForgeAccountIDParams{
		Provider:       strings.TrimSpace(provider),
		ForgeAccountID: nullString(accountID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromFields(row.ID, row.Name, row.Slug, row.DisplayName, row.Provider, row.Settings, row.CreatedAt, row.UpdatedAt).withForgeAccount(row.ForgeAccountID, row.ForgeAccountLogin), nil
}

// SetOrganizationForgeAccount records the forge account an org is bound to.
// An empty accountID only refreshes the login. The id is write-once: the
// update is a no-op on an org already bound to a different id.
func (q *Queries) SetOrganizationForgeAccount(ctx context.Context, orgID uuid.UUID, accountID, accountLogin string) error {
	return q.db.SetOrganizationForgeAccount(ctx, dbgen.SetOrganizationForgeAccountParams{
		ID:           orgID,
		AccountID:    nullString(strings.TrimSpace(accountID)),
		AccountLogin: nullString(strings.TrimSpace(accountLogin)),
	})
}

// OwnsForgeOwner reports whether a repository owner (the namespace part of
// owner/name) belongs to the forge account this org is bound to. Installation
// tokens are minted by owner, so every repo-scoped forge call made on behalf
// of an org must pass this check first, or one tenant can borrow another
// tenant's installation (security audit §3.1).
//
// The verified login is authoritative when recorded. Legacy orgs without one
// fall back to the immutable slug, which provisioning derived from the login.
// Nested namespaces (GitLab subgroups) belong to their top-level account.
func (o *Organization) OwnsForgeOwner(owner string) bool {
	if o == nil {
		return false
	}
	owner = strings.Trim(strings.TrimSpace(owner), "/")
	if owner == "" {
		return false
	}
	top := owner
	if i := strings.Index(top, "/"); i >= 0 {
		top = top[:i]
	}
	if login := strings.TrimSpace(o.ForgeAccountLogin); login != "" {
		return strings.EqualFold(top, login) || strings.EqualFold(owner, login)
	}
	slug := strings.TrimSpace(o.Slug)
	if slug == "" {
		return false
	}
	return strings.EqualFold(top, slug) || SlugifyForgeAccount(top) == strings.ToLower(slug)
}

// SlugifyForgeAccount maps a forge login to the org slug provisioning gives
// it. Lossy on purpose (URL-safe), so it must never serve as identity on its
// own: matching uses the forge account id or the exact login when known.
func SlugifyForgeAccount(login string) string {
	normalized := strings.ToLower(strings.TrimSpace(login))
	if normalized == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(normalized))
	lastWasHyphen := false
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastWasHyphen = false
			continue
		}
		if lastWasHyphen {
			continue
		}
		builder.WriteByte('-')
		lastWasHyphen = true
	}

	slug := strings.Trim(builder.String(), "-")
	if len(slug) > 63 {
		slug = strings.TrimRight(slug[:63], "-")
	}
	return slug
}

// BoundForgeAccount is the forge login inventory lookups for this org are
// scoped to: the verified login, else the slug provisioning derived from it.
func (o *Organization) BoundForgeAccount() string {
	if o == nil {
		return ""
	}
	if login := strings.TrimSpace(o.ForgeAccountLogin); login != "" {
		return login
	}
	return strings.TrimSpace(o.Slug)
}
