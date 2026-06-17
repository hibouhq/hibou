package orgprovision

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

var ErrForgeOrgUnauthorized = errors.New("orgprovision: requester is not a verified forge admin of this account")

type OnboardableAccount struct {
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Slug     string `json:"slug"`
	Status   string `json:"status"`
}

type Store interface {
	UpsertForgeOrgAdmin(ctx context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error)
	SetForgeOrgAdminOrg(ctx context.Context, provider, account, providerUserID string, orgID uuid.UUID) error
	MarkForgeOrgAdminGranted(ctx context.Context, id uuid.UUID) error
	ListPendingForgeOrgAdminsByUser(ctx context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error)
	ListForgeOrgAdminsByUser(ctx context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error)
	GetForgeOrgAdmin(ctx context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error)
	ForgeOrgAdminBindingExists(ctx context.Context, provider string, orgID uuid.UUID) (bool, error)
	GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*store.Organization, error)
	CreateOrganization(ctx context.Context, name, slug, displayName, provider string) (*store.Organization, error)
	AddOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error
	UpsertOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error
	GetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID) (string, error)
	CreateClient(ctx context.Context, orgID uuid.UUID, name, slug string, labels json.RawMessage, clientType string, contactEmail, contactName *string, notificationPrefs, metadata json.RawMessage) (*store.Client, error)
	GetUserByProviderID(ctx context.Context, provider, providerID string) (*store.User, error)
}

type RBACSeeder interface {
	SeedOrgPolicies(orgID uuid.UUID) error
	AddRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error
}

type Service struct {
	store         Store
	rbac          RBACSeeder
	forges        map[string]forge.Provider
	autoProvision bool
	log           zerolog.Logger
}

func NewService(store Store, rbac RBACSeeder, forges map[string]forge.Provider, autoProvision bool, log zerolog.Logger) *Service {
	if forges == nil {
		forges = map[string]forge.Provider{}
	}
	return &Service{
		store:         store,
		rbac:          rbac,
		forges:        forges,
		autoProvision: autoProvision,
		log:           log.With().Str("component", "orgprovision").Logger(),
	}
}

func (s *Service) RecordInstallation(ctx context.Context, providerID string, ev forge.InstallationEvent) error {
	if s.store == nil || !strings.EqualFold(strings.TrimSpace(ev.Action), "created") {
		return nil
	}

	account := strings.TrimSpace(ev.Installation.AccountName)
	installerID := strings.TrimSpace(ev.Sender.ProviderID)
	if account == "" || installerID == "" {
		return nil
	}

	admin, err := s.store.UpsertForgeOrgAdmin(ctx, providerID, account, installerID)
	if err != nil {
		return err
	}
	if !s.autoProvision {
		return nil
	}

	slug := slugifyAccount(account)
	if !api.IsValidSlug(slug) {
		s.log.Warn().Str("provider", strings.TrimSpace(providerID)).Str("account", account).Str("slug", slug).Msg("skipping forge org auto-provision due to invalid slug")
		return nil
	}

	org, err := s.store.GetOrganizationByProviderAndSlug(ctx, providerID, slug)
	if err != nil {
		return err
	}
	orgPreexisted := org != nil
	if org == nil {
		org, err = s.store.CreateOrganization(ctx, account, slug, account, providerID)
		if err != nil {
			if !isUniqueViolation(err) {
				return err
			}
			org, err = s.store.GetOrganizationByProviderAndSlug(ctx, providerID, slug)
			if err != nil {
				return err
			}
			orgPreexisted = true
		}
	}
	if org == nil {
		return nil
	}
	if orgPreexisted {
		bound, err := s.store.ForgeOrgAdminBindingExists(ctx, providerID, org.ID)
		if err != nil {
			return err
		}
		if !bound {
			s.log.Warn().
				Str("provider", strings.TrimSpace(providerID)).
				Str("account", account).
				Str("slug", slug).
				Str("org_id", org.ID.String()).
				Msg("forge org slug already exists and is not provisioning-owned; skipping auto-provision to avoid binding to a foreign organization")
			return nil
		}
	}

	if _, err := s.store.CreateClient(ctx, org.ID, "Internal", "internal", nil, "internal", nil, nil, nil, nil); err != nil && !isUniqueViolation(err) {
		return err
	}
	if s.rbac != nil {
		if err := s.rbac.SeedOrgPolicies(org.ID); err != nil {
			return err
		}
	}
	if err := s.store.SetForgeOrgAdminOrg(ctx, providerID, account, installerID, org.ID); err != nil {
		return err
	}

	if admin != nil && admin.OrgID == nil {
		admin.OrgID = &org.ID
	}
	user, err := s.store.GetUserByProviderID(ctx, providerID, installerID)
	if err != nil {
		return err
	}
	if user == nil || admin == nil {
		return nil
	}

	if err := s.ensureOrgAdmin(ctx, org.ID, user.ID); err != nil {
		return err
	}
	if s.rbac != nil {
		if err := s.rbac.AddRoleForUserInOrg(user.ID, "admin", org.ID); err != nil {
			return err
		}
	}
	return s.store.MarkForgeOrgAdminGranted(ctx, admin.ID)
}

func (s *Service) ClaimPendingAdmin(ctx context.Context, user *store.User) error {
	if s.store == nil || user == nil {
		return nil
	}
	provider := strings.TrimSpace(user.Provider)
	providerUserID := strings.TrimSpace(user.ProviderID)
	if provider == "" || providerUserID == "" {
		return nil
	}

	rows, err := s.store.ListPendingForgeOrgAdminsByUser(ctx, provider, providerUserID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.OrgID == nil || *row.OrgID == uuid.Nil {
			continue
		}
		if err := s.ensureOrgAdmin(ctx, *row.OrgID, user.ID); err != nil {
			s.log.Error().Err(err).Str("org_id", row.OrgID.String()).Str("user_id", user.ID.String()).Msg("failed to claim pending forge org admin")
			return err
		}
		if s.rbac != nil {
			if err := s.rbac.AddRoleForUserInOrg(user.ID, "admin", *row.OrgID); err != nil {
				s.log.Error().Err(err).Str("org_id", row.OrgID.String()).Str("user_id", user.ID.String()).Msg("failed to assign pending forge org admin RBAC role")
				return err
			}
		}
		if err := s.store.MarkForgeOrgAdminGranted(ctx, row.ID); err != nil {
			s.log.Error().Err(err).Str("forge_org_admin_id", row.ID.String()).Msg("failed to mark forge org admin granted")
			return err
		}
	}

	return nil
}

func (s *Service) AuthorizeForgeOrgCreation(ctx context.Context, requester *store.User, providerID, slug string) error {
	provider := s.forges[strings.TrimSpace(providerID)]
	if provider == nil {
		return nil
	}
	if requester == nil || strings.TrimSpace(requester.ProviderID) == "" {
		return ErrForgeOrgUnauthorized
	}
	if !strings.EqualFold(strings.TrimSpace(requester.Provider), strings.TrimSpace(providerID)) {
		return ErrForgeOrgUnauthorized
	}

	installations, err := provider.Installations(ctx)
	if err != nil {
		return err
	}
	matchedAccount := ""
	for _, installation := range installations {
		if slugifyAccount(installation.AccountName) == slugifyAccount(slug) {
			matchedAccount = strings.TrimSpace(installation.AccountName)
			break
		}
	}
	if matchedAccount == "" {
		return ErrForgeOrgUnauthorized
	}

	admin, err := s.store.GetForgeOrgAdmin(ctx, providerID, matchedAccount, requester.ProviderID)
	if err != nil {
		return err
	}
	if admin == nil {
		return ErrForgeOrgUnauthorized
	}
	return nil
}

func (s *Service) ListOnboardableAccounts(ctx context.Context, user *store.User) ([]OnboardableAccount, error) {
	if s.store == nil || user == nil {
		return nil, nil
	}

	providerID := strings.TrimSpace(user.Provider)
	providerUserID := strings.TrimSpace(user.ProviderID)
	if providerID == "" || providerUserID == "" {
		return nil, nil
	}

	provider := s.forges[providerID]
	if provider == nil {
		return []OnboardableAccount{}, nil
	}

	admins, err := s.store.ListForgeOrgAdminsByUser(ctx, providerID, providerUserID)
	if err != nil {
		return nil, err
	}
	if len(admins) == 0 {
		return []OnboardableAccount{}, nil
	}

	installations, err := provider.Installations(ctx)
	if err != nil {
		return nil, err
	}
	liveAccounts := make(map[string]string, len(installations))
	for _, installation := range installations {
		account := strings.TrimSpace(installation.AccountName)
		if account == "" {
			continue
		}
		liveAccounts[slugifyAccount(account)] = account
	}

	accounts := make([]OnboardableAccount, 0, len(admins))
	for _, admin := range admins {
		normalizedAccount := slugifyAccount(admin.Account)
		liveAccount, ok := liveAccounts[normalizedAccount]
		if !ok {
			continue
		}

		slug := slugifyAccount(admin.Account)
		status := "importable"
		if admin.OrgID != nil && *admin.OrgID != uuid.Nil {
			role, err := s.store.GetOrgMemberRole(ctx, *admin.OrgID, user.ID)
			if err != nil {
				return nil, err
			}
			if role != "" {
				status = "imported"
			} else {
				status = "pending"
			}
		}

		accounts = append(accounts, OnboardableAccount{
			Provider: providerID,
			Account:  liveAccount,
			Slug:     slug,
			Status:   status,
		})
	}

	return accounts, nil
}

func (s *Service) ensureOrgAdmin(ctx context.Context, orgID, userID uuid.UUID) error {
	if s.store == nil || orgID == uuid.Nil || userID == uuid.Nil {
		return nil
	}
	role, err := s.store.GetOrgMemberRole(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if role == "admin" {
		return nil
	}
	return s.store.UpsertOrgMemberRole(ctx, orgID, userID, "admin")
}

func slugifyAccount(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return true
	}
	type sqlStateError interface {
		SQLState() string
	}
	var stateErr sqlStateError
	return errors.As(err, &stateErr) && stateErr.SQLState() == "23505"
}
