package permissionsync

import (
	"context"
	"time"

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

func (a *StoreAdapter) UpsertForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string, repoScoped bool) error {
	return a.queries.UpsertForgeOrgMemberScoped(ctx, orgID, userID, role, repoScoped)
}

func (a *StoreAdapter) ListRepositoryIDsByOrg(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return a.queries.ListRepositoryIDsByOrg(ctx, orgID)
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

// SuspendLocalRoles parks a user's operator-granted roles in one org.
func (a *StoreAdapter) SuspendLocalRoles(ctx context.Context, userID, orgID uuid.UUID, reason string) ([]store.LocalRoleGrant, error) {
	return a.queries.SuspendLocalRoles(ctx, userID, orgID, reason)
}

// RevokeLocalRolesForOrg drops grants that ended with a membership.
func (a *StoreAdapter) RevokeLocalRolesForOrg(ctx context.Context, userID, orgID uuid.UUID) error {
	return a.queries.RevokeLocalRolesForOrg(ctx, userID, orgID)
}

// ListStaleForgeOrgMemberships lists forge memberships due for re-validation.
func (a *StoreAdapter) ListStaleForgeOrgMemberships(ctx context.Context, staleBefore time.Time, limit int) ([]store.StaleForgeOrgMembership, error) {
	return a.queries.ListStaleForgeOrgMemberships(ctx, staleBefore, limit)
}

// ListForgeOrgMemberLogins lists org-wide forge members with a known login.
func (a *StoreAdapter) ListForgeOrgMemberLogins(ctx context.Context, orgID uuid.UUID, limit int) (map[uuid.UUID]string, error) {
	return a.queries.ListForgeOrgMemberLogins(ctx, orgID, limit)
}

// TouchForgeOrgMember records a forge membership confirmation.
func (a *StoreAdapter) TouchForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	return a.queries.TouchForgeOrgMember(ctx, orgID, userID)
}

// RemoveForgeOrgAccess drops a forge membership and its repository grants.
func (a *StoreAdapter) RemoveForgeOrgAccess(ctx context.Context, orgID, userID uuid.UUID) error {
	return a.queries.RemoveForgeOrgAccess(ctx, orgID, userID)
}
