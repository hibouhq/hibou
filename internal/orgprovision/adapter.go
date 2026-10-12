package orgprovision

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) UpsertForgeOrgAdmin(ctx context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error) {
	return a.queries.UpsertForgeOrgAdmin(ctx, provider, account, providerUserID)
}

func (a *StoreAdapter) SetForgeOrgAdminOrg(ctx context.Context, provider, account, providerUserID string, orgID uuid.UUID) error {
	return a.queries.SetForgeOrgAdminOrg(ctx, provider, account, providerUserID, orgID)
}

func (a *StoreAdapter) MarkForgeOrgAdminGranted(ctx context.Context, id uuid.UUID) error {
	return a.queries.MarkForgeOrgAdminGranted(ctx, id)
}

func (a *StoreAdapter) ListPendingForgeOrgAdminsByUser(ctx context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error) {
	return a.queries.ListPendingForgeOrgAdminsByUser(ctx, provider, providerUserID)
}

func (a *StoreAdapter) ListForgeOrgAdminsByUser(ctx context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error) {
	return a.queries.ListForgeOrgAdminsByUser(ctx, provider, providerUserID)
}

func (a *StoreAdapter) GetForgeOrgAdmin(ctx context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error) {
	return a.queries.GetForgeOrgAdmin(ctx, provider, account, providerUserID)
}

func (a *StoreAdapter) ForgeOrgAdminBindingExists(ctx context.Context, provider string, orgID uuid.UUID) (bool, error) {
	return a.queries.ForgeOrgAdminBindingExists(ctx, provider, orgID)
}

func (a *StoreAdapter) GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*store.Organization, error) {
	return a.queries.GetOrganizationByProviderAndSlug(ctx, provider, slug)
}

func (a *StoreAdapter) CreateOrganization(ctx context.Context, name, slug, displayName, provider string) (*store.Organization, error) {
	return a.queries.CreateOrganization(ctx, name, slug, displayName, provider)
}

func (a *StoreAdapter) AddOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return a.queries.AddOrgMember(ctx, orgID, userID, role)
}

func (a *StoreAdapter) UpsertOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return a.queries.UpsertOrgMemberRole(ctx, orgID, userID, role)
}

func (a *StoreAdapter) RemoveOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	return a.queries.RemoveOrgMember(ctx, orgID, userID)
}

func (a *StoreAdapter) GetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID) (string, error) {
	return a.queries.GetOrgMemberRole(ctx, orgID, userID)
}

func (a *StoreAdapter) CreateClient(ctx context.Context, orgID uuid.UUID, name, slug string, labels json.RawMessage, clientType string, contactEmail, contactName *string, notificationPrefs, metadata json.RawMessage) (*store.Client, error) {
	return a.queries.CreateClient(ctx, orgID, name, slug, labels, clientType, contactEmail, contactName, notificationPrefs, metadata)
}

func (a *StoreAdapter) GetUserByProviderID(ctx context.Context, provider, providerID string) (*store.User, error) {
	return a.queries.GetUserByProviderID(ctx, provider, providerID)
}

func (a *StoreAdapter) GetOrganizationByForgeAccountID(ctx context.Context, provider, accountID string) (*store.Organization, error) {
	return a.queries.GetOrganizationByForgeAccountID(ctx, provider, accountID)
}

func (a *StoreAdapter) SetOrganizationForgeAccount(ctx context.Context, orgID uuid.UUID, accountID, accountLogin string) error {
	return a.queries.SetOrganizationForgeAccount(ctx, orgID, accountID, accountLogin)
}

func (a *StoreAdapter) DeleteForgeOrgAdminsByAccount(ctx context.Context, provider, account string) ([]store.ForgeOrgAdmin, error) {
	return a.queries.DeleteForgeOrgAdminsByAccount(ctx, provider, account)
}

func (a *StoreAdapter) ListOrganizations(ctx context.Context) ([]store.Organization, error) {
	return a.queries.ListOrganizations(ctx)
}
