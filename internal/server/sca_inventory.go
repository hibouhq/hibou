package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/hibouhq/hibou/internal/store"
)

// Old discovery rows predate account_id. Verify their recorded repository ID
// against the bound account before filling metadata; never bind by name alone.
func (s *Server) refreshSCAInventoryMetadata(ctx context.Context, org *store.Organization, providerID string) error {
	if strings.TrimSpace(org.ForgeAccountID) == "" || strings.TrimSpace(org.ForgeAccountLogin) == "" {
		return &scaEnableError{"This organization has no verified forge account binding. Verify or reconnect its App installation before enabling SCA."}
	}
	inv, err := s.queries.GetForgeRepositoryForAccount(ctx, org.Provider, org.BoundForgeAccount(), providerID)
	if err != nil {
		return fmt.Errorf("load SCA discovery metadata: %w", err)
	}
	if inv == nil {
		return &scaEnableError{"Repository is no longer in this organization's accessible forge inventory. Sync repositories and retry."}
	}
	if inv.Archived {
		return &scaEnableError{"Archived repositories cannot enable automatic SCA. Unarchive the repository on the forge first."}
	}
	if !org.OwnsForgeOwner(inv.Owner) || inv.AccountID != "" && inv.AccountID != org.ForgeAccountID {
		return &scaEnableError{"Repository account identity does not match this organization's verified forge account. Sync the App installation; SCA was not enabled."}
	}
	if inv.ProviderRepoID == nil || strings.TrimSpace(*inv.ProviderRepoID) == "" {
		return &scaEnableError{"Repository discovery has no immutable repository ID. Sync the App installation before enabling SCA."}
	}
	if inv.AccountID != "" && strings.TrimSpace(inv.DefaultBranch) != "" {
		return nil
	}
	provider := s.forges[org.Provider]
	if provider == nil {
		return &scaEnableError{"This organization's forge provider is not configured on this instance."}
	}
	live, err := provider.GetRepository(ctx, inv.Owner, inv.Name)
	if err != nil {
		return fmt.Errorf("%w: %w",
			&scaEnableError{"Hibou could not verify current repository access with the forge. Check the App installation's repository access and retry."}, err)
	}
	if live == nil || live.OwnerID != org.ForgeAccountID || live.ProviderRepoID != *inv.ProviderRepoID ||
		normalizeInventoryRepoKey(live.FullName) != normalizeInventoryRepoKey(inv.ProviderKey) ||
		!org.OwnsForgeOwner(live.Owner) {
		return &scaEnableError{"The live repository identity differs from its discovered identity. Sync repositories and verify the App installation; SCA was not enabled."}
	}
	if live.Archived {
		return &scaEnableError{"The repository is archived on the forge. Unarchive it before enabling automatic SCA."}
	}
	if strings.TrimSpace(live.DefaultBranch) == "" {
		return &scaEnableError{"The repository has no default branch to extract. Create its initial branch before enabling SCA."}
	}
	updated, err := s.queries.RefreshVerifiedForgeRepositoryMetadata(ctx, inv.ID, org.ID,
		live.OwnerID, live.ProviderRepoID, live.DefaultBranch, inv.UpdatedAt)
	if err != nil {
		return fmt.Errorf("refresh verified SCA discovery metadata: %w", err)
	}
	if updated {
		return nil
	}
	current, err := s.queries.GetForgeRepositoryForAccount(ctx, org.Provider, org.BoundForgeAccount(), providerID)
	if err != nil {
		return fmt.Errorf("reload SCA discovery metadata: %w", err)
	}
	if current != nil && !current.Archived && current.AccountID == org.ForgeAccountID &&
		current.ProviderRepoID != nil && *current.ProviderRepoID == live.ProviderRepoID &&
		org.OwnsForgeOwner(current.Owner) && strings.TrimSpace(current.DefaultBranch) != "" {
		return nil
	}
	return &scaEnableError{"Repository access or identity changed while it was being verified. Refresh the repository list and retry."}
}
