package orgprovision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// ForgeAccountStore persists the org ↔ forge account binding (security audit
// §3.3). Optional so narrow test stores keep compiling; StoreAdapter has it,
// and without it provisioning falls back to slug matching only.
type ForgeAccountStore interface {
	GetOrganizationByForgeAccountID(ctx context.Context, provider, accountID string) (*store.Organization, error)
	SetOrganizationForgeAccount(ctx context.Context, orgID uuid.UUID, accountID, accountLogin string) error
	DeleteForgeOrgAdminsByAccount(ctx context.Context, provider, account string) ([]store.ForgeOrgAdmin, error)
	ListOrganizations(ctx context.Context) ([]store.Organization, error)
}

// AccountIDResolver maps installed accounts' lowercased logins to their
// immutable forge account ids.
type AccountIDResolver interface {
	InstallationAccountIDs(ctx context.Context) (map[string]string, error)
}

// InstallationVerifier is implemented by forges whose App API can confirm an
// installation independently of the webhook that announced it.
type InstallationVerifier interface {
	GetInstallationAccount(ctx context.Context, installationID int64) (*forge.InstallationAccount, error)
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
	if s.store == nil {
		return nil
	}
	// "created" fires once and expires. The others prove the same admin rights and
	// can be re-fired from App settings. "suspend"/"deleted" revoke access.
	switch strings.ToLower(strings.TrimSpace(ev.Action)) {
	case "created", "unsuspend", "new_permissions_accepted":
	case "deleted", "suspend":
		return s.revokeInstallationAccess(ctx, providerID, ev.Installation)
	default:
		return nil
	}
	return s.recordVerifiedInstallationAccess(ctx, providerID, ev.Installation, ev.Sender.ProviderID)
}

// RecordInstallationRepositories provisions from a repository-selection change.
// Same admin proof as an install, but re-triggerable, so a rebuilt database has
// a way back to a provisioned org.
func (s *Service) RecordInstallationRepositories(ctx context.Context, providerID string, ev forge.InstallationRepositoriesEvent) error {
	if s.store == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(ev.Action)) {
	case "added", "removed":
	default:
		return nil
	}
	return s.recordVerifiedInstallationAccess(ctx, providerID, ev.Installation, ev.Sender.ProviderID)
}

// verifiedAccount is the forge account an installation event is about, as the
// forge's own API reports it rather than as the payload claims.
type verifiedAccount struct {
	id    string // immutable forge account id; empty when the forge cannot say
	login string
}

// errInstallationUnverified marks an event the App API contradicts. It is not
// returned to the webhook caller: the event is dropped and logged.
var errInstallationUnverified = errors.New("orgprovision: installation not confirmed by the forge API")

// verifyInstallation re-reads the installation from the App API before any
// admin grant (security audit §3.4): the installation must exist, must not be
// suspended, and its account must be the one the payload names. The verified
// account id is what the org binds to. Forges without an App API (no
// InstallationVerifier) keep the payload login and no id.
func (s *Service) verifyInstallation(ctx context.Context, providerID string, installation forge.Installation) (verifiedAccount, error) {
	login := strings.TrimSpace(installation.AccountName)
	verifier, ok := s.forges[strings.TrimSpace(providerID)].(InstallationVerifier)
	if !ok {
		return verifiedAccount{login: login}, nil
	}
	account, err := verifier.GetInstallationAccount(ctx, installation.ID)
	if errors.Is(err, forge.ErrInstallationNotFound) {
		return verifiedAccount{}, fmt.Errorf("%w: installation %d does not exist", errInstallationUnverified, installation.ID)
	}
	if err != nil {
		return verifiedAccount{}, err
	}
	if account == nil || account.Suspended {
		return verifiedAccount{}, fmt.Errorf("%w: installation %d is suspended", errInstallationUnverified, installation.ID)
	}
	if !strings.EqualFold(strings.TrimSpace(account.AccountLogin), login) {
		return verifiedAccount{}, fmt.Errorf("%w: installation %d belongs to %q, not %q", errInstallationUnverified, installation.ID, account.AccountLogin, login)
	}
	return verifiedAccount{id: strings.TrimSpace(account.AccountID), login: strings.TrimSpace(account.AccountLogin)}, nil
}

func (s *Service) recordVerifiedInstallationAccess(ctx context.Context, providerID string, installation forge.Installation, senderProviderID string) error {
	if strings.TrimSpace(installation.AccountName) == "" || strings.TrimSpace(senderProviderID) == "" {
		return nil
	}
	account, err := s.verifyInstallation(ctx, providerID, installation)
	if errors.Is(err, errInstallationUnverified) {
		s.log.Warn().Err(err).Str("provider", strings.TrimSpace(providerID)).Str("account", installation.AccountName).Msg("ignoring installation event the forge API does not confirm")
		return nil
	}
	if err != nil {
		return err
	}
	return s.recordInstallationAccess(ctx, providerID, account, senderProviderID)
}

// revokeInstallationAccess drops the forge-admin bindings of an account whose
// installation was deleted or suspended (audit A11): they were the proof of
// admin rights, and a pending claim must not be redeemable after the App is
// gone. Org memberships already granted are left to the permission sync.
// When the App API still reports the installation live and unsuspended, the
// event is stale or forged and is ignored.
func (s *Service) revokeInstallationAccess(ctx context.Context, providerID string, installation forge.Installation) error {
	login := strings.TrimSpace(installation.AccountName)
	if login == "" {
		return nil
	}
	if verifier, ok := s.forges[strings.TrimSpace(providerID)].(InstallationVerifier); ok {
		account, err := verifier.GetInstallationAccount(ctx, installation.ID)
		switch {
		case errors.Is(err, forge.ErrInstallationNotFound):
		case err != nil:
			return err
		case account != nil && !account.Suspended:
			s.log.Warn().Str("provider", strings.TrimSpace(providerID)).Str("account", login).Int64("installation_id", installation.ID).Msg("ignoring uninstall event for an installation the forge API reports live")
			return nil
		case account != nil && !strings.EqualFold(strings.TrimSpace(account.AccountLogin), login):
			s.log.Warn().Str("provider", strings.TrimSpace(providerID)).Str("account", login).Int64("installation_id", installation.ID).Msg("ignoring uninstall event naming another account")
			return nil
		}
	}
	accounts, ok := s.store.(ForgeAccountStore)
	if !ok {
		return nil
	}
	removed, err := accounts.DeleteForgeOrgAdminsByAccount(ctx, providerID, login)
	if err != nil {
		return err
	}
	if len(removed) > 0 {
		s.log.Info().Str("provider", strings.TrimSpace(providerID)).Str("account", login).Int("bindings", len(removed)).Msg("revoked forge org admin bindings after uninstall")
	}
	return nil
}

// recordInstallationAccess binds the account to its admin and, when
// auto-provisioning is on, creates the org.
func (s *Service) recordInstallationAccess(ctx context.Context, providerID string, verified verifiedAccount, senderProviderID string) error {
	account := strings.TrimSpace(verified.login)
	installerID := strings.TrimSpace(senderProviderID)
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

	org, ok, err := s.resolveProvisionedOrg(ctx, providerID, verified, installerID)
	if err != nil || !ok {
		return err
	}
	if accounts, ok := s.store.(ForgeAccountStore); ok {
		if err := accounts.SetOrganizationForgeAccount(ctx, org.ID, verified.id, account); err != nil {
			return err
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

// resolveProvisionedOrg finds or creates the org bound to the account. The
// immutable account id wins: it follows a renamed account to its existing org
// and stops a newcomer who registers the old login from inheriting it
// (security audit §3.3). The slug is only a fallback, and a slug-matched org
// already bound to a different account — a different id, a different exact
// login (GitLab "acme_corp" vs "acme.corp"), or none of this account's admin
// bindings — is never adopted.
func (s *Service) resolveProvisionedOrg(ctx context.Context, providerID string, verified verifiedAccount, installerID string) (*store.Organization, bool, error) {
	account := verified.login
	if accounts, ok := s.store.(ForgeAccountStore); ok && verified.id != "" {
		org, err := accounts.GetOrganizationByForgeAccountID(ctx, providerID, verified.id)
		if err != nil {
			return nil, false, err
		}
		if org != nil {
			return org, true, nil
		}
	}

	slug := slugifyAccount(account)
	if !api.IsValidSlug(slug) {
		s.log.Warn().Str("provider", strings.TrimSpace(providerID)).Str("account", account).Str("slug", slug).Msg("skipping forge org auto-provision due to invalid slug")
		return nil, false, nil
	}

	org, err := s.store.GetOrganizationByProviderAndSlug(ctx, providerID, slug)
	if err != nil {
		return nil, false, err
	}
	if org == nil {
		org, err = s.store.CreateOrganization(ctx, account, slug, account, providerID)
		if err == nil {
			return org, org != nil, nil
		}
		if !isUniqueViolation(err) {
			return nil, false, err
		}
		org, err = s.store.GetOrganizationByProviderAndSlug(ctx, providerID, slug)
		if err != nil || org == nil {
			return nil, false, err
		}
	}

	logForeign := func(reason string) {
		s.log.Warn().
			Str("provider", strings.TrimSpace(providerID)).
			Str("account", account).
			Str("account_id", verified.id).
			Str("slug", slug).
			Str("org_id", org.ID.String()).
			Msg("forge org slug already exists and is bound to another account (" + reason + "); skipping auto-provision to avoid binding to a foreign organization")
	}
	if org.ForgeAccountID != "" {
		// The id lookup above missed, so this org belongs to another account.
		logForeign("account id differs")
		return nil, false, nil
	}
	if org.ForgeAccountLogin != "" && !strings.EqualFold(org.ForgeAccountLogin, account) {
		logForeign("login differs")
		return nil, false, nil
	}
	bound, err := s.store.ForgeOrgAdminBindingExists(ctx, providerID, org.ID)
	if err != nil {
		return nil, false, err
	}
	if !bound && org.ForgeAccountLogin == "" {
		logForeign("not provisioning-owned")
		return nil, false, nil
	}
	if verified.id != "" {
		// A legacy org (login, no id) whose login now names an account id we
		// have never seen: the original account may have been renamed and
		// its login re-registered. Only someone the org already trusts may
		// adopt it — the installer recorded for it, or one of its admins.
		trusted, err := s.installerTrustedByOrg(ctx, providerID, account, installerID, org.ID)
		if err != nil {
			return nil, false, err
		}
		if !trusted {
			logForeign("no account id recorded and the installer is not its recorded admin")
			return nil, false, nil
		}
	}
	return org, true, nil
}

// installerTrustedByOrg reports whether the installer already holds this org:
// a forge-admin binding to it, or an admin membership in it.
func (s *Service) installerTrustedByOrg(ctx context.Context, providerID, account, installerID string, orgID uuid.UUID) (bool, error) {
	admin, err := s.store.GetForgeOrgAdmin(ctx, providerID, account, installerID)
	if err != nil {
		return false, err
	}
	if admin != nil && admin.OrgID != nil && *admin.OrgID == orgID {
		return true, nil
	}
	user, err := s.store.GetUserByProviderID(ctx, providerID, installerID)
	if err != nil || user == nil {
		return false, err
	}
	role, err := s.store.GetOrgMemberRole(ctx, orgID, user.ID)
	if err != nil {
		return false, err
	}
	return role == "admin", nil
}

// BackfillForgeAccountIDs binds orgs that predate account-id tracking (a
// recorded login, no id) to the id their login maps to among the App's live
// installations. Login-only orgs can be taken over by whoever registers a
// renamed account's old login; running this at startup closes that window
// for every account the App is still installed on.
func (s *Service) BackfillForgeAccountIDs(ctx context.Context) error {
	accounts, ok := s.store.(ForgeAccountStore)
	if !ok {
		return nil
	}
	orgs, err := accounts.ListOrganizations(ctx)
	if err != nil {
		return err
	}
	idsByProvider := make(map[string]map[string]string)
	for i := range orgs {
		org := orgs[i]
		login := strings.ToLower(strings.TrimSpace(org.ForgeAccountLogin))
		if org.ForgeAccountID != "" || login == "" {
			continue
		}
		ids, seen := idsByProvider[org.Provider]
		if !seen {
			if resolver, ok := s.forges[org.Provider].(AccountIDResolver); ok {
				if ids, err = resolver.InstallationAccountIDs(ctx); err != nil {
					return err
				}
			}
			idsByProvider[org.Provider] = ids
		}
		id := ids[login]
		if id == "" {
			continue
		}
		if err := accounts.SetOrganizationForgeAccount(ctx, org.ID, id, org.ForgeAccountLogin); err != nil {
			if isUniqueViolation(err) {
				s.log.Warn().Str("org_id", org.ID.String()).Str("account", org.ForgeAccountLogin).Msg("forge account id already bound to another org; leaving org unbound")
				continue
			}
			return err
		}
	}
	return nil
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
	_, err := s.AuthorizeForgeOrgCreationAccount(ctx, requester, providerID, slug)
	return err
}

// ForgeAccount is the forge account a manually created org binds to.
type ForgeAccount struct {
	// Login is the installed account's login; empty when the provider is
	// not configured (development), in which case nothing is bound.
	Login string
	// ID is the immutable account id, when the forge can tell.
	ID string
}

// AuthorizeForgeOrgCreationAccount authorizes POST /orgs like
// AuthorizeForgeOrgCreation and returns the installed account the new org
// must be bound to. Binding at creation is what makes forge calls for the
// org's repositories owner-checked from the first one (security audit §3.1)
// and stops a later rename of the account from handing the org over (§3.3).
func (s *Service) AuthorizeForgeOrgCreationAccount(ctx context.Context, requester *store.User, providerID, slug string) (ForgeAccount, error) {
	provider := s.forges[strings.TrimSpace(providerID)]
	if provider == nil {
		return ForgeAccount{}, nil
	}
	if requester == nil || strings.TrimSpace(requester.ProviderID) == "" {
		return ForgeAccount{}, ErrForgeOrgUnauthorized
	}
	if !strings.EqualFold(strings.TrimSpace(requester.Provider), strings.TrimSpace(providerID)) {
		return ForgeAccount{}, ErrForgeOrgUnauthorized
	}

	installations, err := provider.Installations(ctx)
	if err != nil {
		return ForgeAccount{}, err
	}
	matchedSlug := slugifyAccount(slug)
	for _, installation := range installations {
		if slugifyAccount(installation.AccountName) != matchedSlug {
			continue
		}
		matchedAccount := strings.TrimSpace(installation.AccountName)

		admin, err := s.store.GetForgeOrgAdmin(ctx, providerID, matchedAccount, requester.ProviderID)
		if err != nil {
			return ForgeAccount{}, err
		}
		if admin == nil {
			continue
		}
		account := ForgeAccount{Login: matchedAccount}
		if resolver, ok := provider.(AccountIDResolver); ok {
			ids, err := resolver.InstallationAccountIDs(ctx)
			if err != nil {
				return ForgeAccount{}, err
			}
			account.ID = ids[strings.ToLower(matchedAccount)]
		}
		return account, nil
	}
	return ForgeAccount{}, ErrForgeOrgUnauthorized
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
	return s.store.UpsertOrgMemberRole(ctx, orgID, userID, "admin")
}

func slugifyAccount(login string) string {
	return store.SlugifyForgeAccount(login)
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
