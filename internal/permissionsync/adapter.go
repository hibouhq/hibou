package permissionsync

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*store.Organization, error) {
	return a.queries.GetOrganizationByProviderAndSlug(ctx, provider, slug)
}

func (a *StoreAdapter) UpsertForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return a.queries.UpsertForgeOrgMember(ctx, orgID, userID, role)
}

func (a *StoreAdapter) ListForgeOrgMembershipsByUser(ctx context.Context, userID uuid.UUID) ([]store.ForgeOrgMembership, error) {
	return a.queries.ListForgeOrgMembershipsByUser(ctx, userID)
}

func (a *StoreAdapter) PruneForgeOrgMembersForUser(ctx context.Context, userID uuid.UUID, keepOrgIDs []uuid.UUID) error {
	return a.queries.PruneForgeOrgMembersForUser(ctx, userID, keepOrgIDs)
}

func (a *StoreAdapter) GetRepositoryBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*store.Repository, error) {
	return a.queries.GetRepositoryBySlug(ctx, orgID, slug)
}

func (a *StoreAdapter) UpsertForgeUserRepoAccess(ctx context.Context, userID, repoID uuid.UUID, role string) error {
	return a.queries.UpsertForgeUserRepoAccess(ctx, userID, repoID, role)
}

func (a *StoreAdapter) PruneForgeUserRepoAccess(ctx context.Context, userID uuid.UUID, keepRepoIDs []uuid.UUID) error {
	return a.queries.PruneForgeUserRepoAccess(ctx, userID, keepRepoIDs)
}
