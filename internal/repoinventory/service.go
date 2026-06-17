package repoinventory

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type Store interface {
	UpsertForgeRepository(ctx context.Context, repository store.ForgeRepository) (*store.ForgeRepositoryUpsertResult, error)
	SoftDeleteForgeRepository(ctx context.Context, provider, providerKey string) (*store.ForgeRepositoryChange, error)
	MarkInstallationRepositoriesRemoved(ctx context.Context, provider string, installationID int64) ([]store.ForgeRepositoryChange, error)
	SetForgeRepositoryArchived(ctx context.Context, provider, providerKey string, archived bool) (*store.ForgeRepositoryChange, error)
	SetForgeRepositoryPrivate(ctx context.Context, provider, providerKey string, private bool) error
	ListForgeRepositoriesByAccount(ctx context.Context, provider, account string) ([]store.ForgeRepository, error)
	GetForgeRepositoryByProviderRepoID(ctx context.Context, provider, id string) (*store.ForgeRepository, error)
	CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error)
	GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*store.Organization, error)
}

type Service struct {
	store  Store
	forges map[string]forge.Provider
	log    zerolog.Logger
}

func NewService(store Store, forges map[string]forge.Provider, log zerolog.Logger) *Service {
	if forges == nil {
		forges = map[string]forge.Provider{}
	}
	return &Service{
		store:  store,
		forges: forges,
		log:    log.With().Str("component", "repoinventory").Logger(),
	}
}

func (s *Service) SeedInstallation(ctx context.Context, providerID string, inst forge.Installation, repos []forge.Repository) error {
	if s.store == nil {
		return nil
	}
	var beforeByKey map[string]store.ForgeRepository
	if current, err := s.store.ListForgeRepositoriesByAccount(ctx, providerID, inst.AccountName); err != nil {
		s.log.Warn().Err(err).Str("provider", providerID).Str("account", strings.TrimSpace(inst.AccountName)).Int64("installation_id", inst.ID).Msg("snapshot installation repositories before seed")
	} else {
		beforeByKey = make(map[string]store.ForgeRepository, len(current))
		for _, repo := range current {
			beforeByKey[repo.ProviderKey] = repo
		}
	}
	if inst.ID > 0 {
		if _, err := s.store.MarkInstallationRepositoriesRemoved(ctx, providerID, inst.ID); err != nil {
			return err
		}
	}
	incomingByKey := make(map[string]*store.ForgeRepository, len(repos))
	for _, repo := range repos {
		result, err := s.upsertRepositoryCore(ctx, providerID, &inst, repo, false)
		if err != nil {
			return err
		}
		providerKey := normalizeRepositoryKey(repo.FullName)
		if result != nil && result.Repository != nil {
			providerKey = result.Repository.ProviderKey
			incomingByKey[providerKey] = result.Repository
			continue
		}
		incomingByKey[providerKey] = nil
	}
	if beforeByKey == nil {
		return nil
	}
	for providerKey, repo := range beforeByKey {
		if _, ok := incomingByKey[providerKey]; ok || inst.ID <= 0 {
			continue
		}
		repoID := repo.ID
		fullName := repo.FullName
		if fullName == "" {
			fullName = providerKey
		}
		s.recordAudit(ctx, providerID, repositoryAccount(inst.AccountName, fullName), audit.ActionRepoDeleted, &repoID, fullName, map[string]any{"reason": "reconcile_removed"})
	}
	for providerKey, repo := range incomingByKey {
		if _, ok := beforeByKey[providerKey]; ok || repo == nil {
			continue
		}
		repoID := repo.ID
		fullName := repo.FullName
		if fullName == "" {
			fullName = providerKey
		}
		s.recordAudit(ctx, providerID, repositoryAccount(inst.AccountName, fullName), audit.ActionRepoDetected, &repoID, fullName, nil)
	}
	return nil
}

func (s *Service) ApplyInstallation(ctx context.Context, providerID string, ev forge.InstallationEvent) error {
	switch strings.ToLower(strings.TrimSpace(ev.Action)) {
	case "created", "new_permissions_accepted", "unsuspend":
		return s.SeedInstallation(ctx, providerID, ev.Installation, ev.Repositories)
	case "deleted", "suspend":
		if ev.Installation.ID <= 0 || s.store == nil {
			return nil
		}
		return s.markInstallationRepositoriesRemoved(ctx, providerID, ev.Installation.ID, ev.Installation.AccountName, "installation_removed")
	default:
		return nil
	}
}

func (s *Service) ApplyInstallationRepositories(ctx context.Context, providerID string, ev forge.InstallationRepositoriesEvent) error {
	for _, repo := range ev.RepositoriesAdded {
		if _, err := s.upsertRepository(ctx, providerID, &ev.Installation, repo, false); err != nil {
			return err
		}
	}
	for _, repo := range ev.RepositoriesRemoved {
		if err := s.softDeleteRepository(ctx, providerID, repositoryAccount(repo.Owner, repo.FullName), repo.FullName, repo.FullName, "installation_repositories_removed"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ApplyRepository(ctx context.Context, providerID string, ev forge.RepositoryEvent) error {
	providerKey, oldProviderKey, err := s.resolveRepositoryKeys(ctx, providerID, ev)
	if err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(ev.Action)) {
	case "created", "publicized", "privatized":
		return s.applyRepositoryUpsert(ctx, providerID, ev.Repo)
	case "renamed", "transferred":
		return s.upsertAndRetirePreviousKey(ctx, providerID, ev.Repo, oldProviderKey)
	case "deleted":
		return s.applyRepositoryDeletion(ctx, providerID, ev.Repo, providerKey, oldProviderKey)
	case "archived":
		return s.applyRepositoryArchive(ctx, providerID, ev.Repo, providerKey, true)
	case "unarchived":
		return s.applyRepositoryArchive(ctx, providerID, ev.Repo, providerKey, false)
	default:
		return nil
	}
}

func (s *Service) resolveRepositoryKeys(ctx context.Context, providerID string, ev forge.RepositoryEvent) (string, string, error) {
	providerKey := strings.TrimSpace(ev.Repo.FullName)
	oldProviderKey := strings.TrimSpace(ev.OldFullName)
	if oldProviderKey != "" || strings.TrimSpace(ev.Repo.ProviderRepoID) == "" || s.store == nil {
		return providerKey, oldProviderKey, nil
	}
	current, err := s.store.GetForgeRepositoryByProviderRepoID(ctx, providerID, ev.Repo.ProviderRepoID)
	if err != nil {
		return "", "", err
	}
	if current != nil {
		oldProviderKey = current.FullName
	}
	return providerKey, oldProviderKey, nil
}

func (s *Service) applyRepositoryUpsert(ctx context.Context, providerID string, repo forge.Repository) error {
	_, err := s.upsertRepository(ctx, providerID, nil, repo, false)
	return err
}

func (s *Service) applyRepositoryDeletion(ctx context.Context, providerID string, repo forge.Repository, providerKey, oldProviderKey string) error {
	if providerKey == "" && oldProviderKey != "" {
		providerKey = oldProviderKey
	}
	if providerKey == "" || s.store == nil {
		return nil
	}
	return s.softDeleteRepository(ctx, providerID, repositoryAccount(repo.Owner, providerKey), providerKey, providerKey, "repository_deleted")
}

func (s *Service) applyRepositoryArchive(ctx context.Context, providerID string, repo forge.Repository, providerKey string, archived bool) error {
	if providerKey == "" || s.store == nil {
		return nil
	}
	return s.setRepositoryArchived(ctx, providerID, repositoryAccount(repo.Owner, providerKey), providerKey, providerKey, archived)
}

func (s *Service) upsertAndRetirePreviousKey(ctx context.Context, providerID string, repo forge.Repository, oldProviderKey string) error {
	upserted, err := s.upsertRepository(ctx, providerID, nil, repo, false)
	if err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	providerKey := normalizeRepositoryKey(repo.FullName)
	oldProviderKey = normalizeRepositoryKey(oldProviderKey)
	if oldProviderKey == "" || oldProviderKey == providerKey {
		return nil
	}
	change, err := s.store.SoftDeleteForgeRepository(ctx, providerID, oldProviderKey)
	if err != nil {
		return err
	}
	if change != nil && upserted != nil && upserted.Repository != nil {
		repoID := upserted.Repository.ID
		oldFullName := change.FullName
		if oldFullName == "" {
			oldFullName = oldProviderKey
		}
		s.recordAudit(ctx, providerID, repositoryAccount(repo.Owner, repo.FullName), audit.ActionRepoRenamed, &repoID, upserted.Repository.FullName, map[string]any{"old_full_name": oldFullName})
	}
	return nil
}

func (s *Service) Sync(ctx context.Context, providerID, account string) error {
	provider := s.forges[strings.TrimSpace(providerID)]
	if provider == nil {
		return nil
	}
	installations, err := provider.Installations(ctx)
	if err != nil {
		return err
	}
	if len(installations) == 0 {
		return nil
	}
	matched, ok := matchInstallationAccount(installations, account)
	if !ok {
		return nil
	}
	repositories, err := provider.ListRepositories(ctx, forge.ListReposOptions{})
	if err != nil {
		return err
	}
	filtered := make([]forge.Repository, 0, len(repositories))
	for _, repo := range repositories {
		if equalAccount(repo.Owner, matched.AccountName) {
			filtered = append(filtered, repo)
		}
	}
	if err := s.SeedInstallation(ctx, providerID, matched, filtered); err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	for _, repo := range filtered {
		if err := s.setRepositoryArchived(ctx, providerID, matched.AccountName, normalizeRepositoryKey(repo.FullName), repo.FullName, repo.Archived); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) upsertRepository(ctx context.Context, providerID string, inst *forge.Installation, repo forge.Repository, archived bool) (*store.ForgeRepositoryUpsertResult, error) {
	result, err := s.upsertRepositoryCore(ctx, providerID, inst, repo, archived)
	if err != nil {
		return nil, err
	}
	if result != nil && result.Repository != nil && (result.Inserted || result.PreviouslyRemoved) {
		repoID := result.Repository.ID
		account := strings.TrimSpace(result.Repository.AccountLogin)
		if account == "" {
			account = repositoryAccount("", result.Repository.FullName)
		}
		s.recordAudit(ctx, providerID, account, audit.ActionRepoDetected, &repoID, result.Repository.FullName, nil)
	}
	return result, nil
}

func (s *Service) upsertRepositoryCore(ctx context.Context, providerID string, inst *forge.Installation, repo forge.Repository, archived bool) (*store.ForgeRepositoryUpsertResult, error) {
	if s.store == nil {
		return nil, nil
	}
	owner := strings.TrimSpace(repo.Owner)
	accountLogin := owner
	var installationID *int64
	if inst != nil {
		accountLogin = strings.TrimSpace(inst.AccountName)
		if accountLogin == "" {
			accountLogin = owner
		}
		if inst.ID > 0 {
			installationID = &inst.ID
		}
	}
	fullName := strings.TrimSpace(repo.FullName)
	if fullName == "" && owner != "" && strings.TrimSpace(repo.Name) != "" {
		fullName = owner + "/" + strings.TrimSpace(repo.Name)
	}
	providerRepoID := stringPtr(strings.TrimSpace(repo.ProviderRepoID))
	result, err := s.store.UpsertForgeRepository(ctx, store.ForgeRepository{
		Provider:       strings.TrimSpace(providerID),
		InstallationID: installationID,
		ProviderRepoID: providerRepoID,
		AccountLogin:   accountLogin,
		Owner:          owner,
		Name:           strings.TrimSpace(repo.Name),
		FullName:       fullName,
		Private:        repo.Private,
		DefaultBranch:  strings.TrimSpace(repo.DefaultBranch),
		HTMLURL:        strings.TrimSpace(repo.HTMLURL),
		Archived:       archived,
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) markInstallationRepositoriesRemoved(ctx context.Context, providerID string, installationID int64, account, reason string) error {
	if s.store == nil {
		return nil
	}
	changes, err := s.store.MarkInstallationRepositoriesRemoved(ctx, providerID, installationID)
	if err != nil {
		return err
	}
	for _, change := range changes {
		repoID := change.ID
		fullName := change.FullName
		if fullName == "" {
			fullName = change.ProviderKey
		}
		s.recordAudit(ctx, providerID, repositoryAccount(account, fullName), audit.ActionRepoDeleted, &repoID, fullName, map[string]any{"reason": reason})
	}
	return nil
}

func (s *Service) softDeleteRepository(ctx context.Context, providerID, account, providerKey, fullName, reason string) error {
	if s.store == nil {
		return nil
	}
	change, err := s.store.SoftDeleteForgeRepository(ctx, providerID, providerKey)
	if err != nil {
		return err
	}
	if change == nil {
		return nil
	}
	repoID := change.ID
	name := change.FullName
	if name == "" {
		name = strings.TrimSpace(fullName)
	}
	s.recordAudit(ctx, providerID, repositoryAccount(account, name), audit.ActionRepoDeleted, &repoID, name, map[string]any{"reason": reason})
	return nil
}

func (s *Service) setRepositoryArchived(ctx context.Context, providerID, account, providerKey, fullName string, archived bool) error {
	if s.store == nil {
		return nil
	}
	change, err := s.store.SetForgeRepositoryArchived(ctx, providerID, providerKey, archived)
	if err != nil {
		return err
	}
	if change == nil {
		return nil
	}
	action := audit.ActionRepoUnarchived
	if archived {
		action = audit.ActionRepoArchived
	}
	repoID := change.ID
	name := change.FullName
	if name == "" {
		name = strings.TrimSpace(fullName)
	}
	s.recordAudit(ctx, providerID, repositoryAccount(account, name), action, &repoID, name, nil)
	return nil
}

func (s *Service) recordAudit(ctx context.Context, providerID, account, action string, repoID *uuid.UUID, fullName string, extra map[string]any) {
	if s.store == nil {
		return
	}
	providerID = strings.TrimSpace(providerID)
	account = strings.TrimSpace(account)
	fullName = strings.TrimSpace(fullName)
	orgID := uuid.NullUUID{}
	if account != "" {
		org, err := s.store.GetOrganizationByProviderAndSlug(ctx, providerID, strings.ToLower(strings.TrimSpace(account)))
		if err == nil && org != nil {
			orgID = uuid.NullUUID{UUID: org.ID, Valid: true}
		}
	}
	auditContext := map[string]any{
		"provider":  providerID,
		"account":   account,
		"full_name": fullName,
	}
	for key, value := range extra {
		auditContext[key] = value
	}
	payload, err := json.Marshal(auditContext)
	if err != nil {
		s.log.Warn().Err(err).Str("provider", providerID).Str("account", account).Str("full_name", fullName).Str("action", action).Msg("marshal repository inventory audit context")
		return
	}
	resourceID := normalizeRepositoryKey(fullName)
	if repoID != nil {
		resourceID = repoID.String()
	}
	if resourceID == "" {
		return
	}
	if _, err := s.store.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorSystem,
		ActorDisplay: "repository-inventory",
		Action:       action,
		ResourceType: "forge_repository",
		ResourceID:   resourceID,
		OrgID:        orgID,
		Context:      payload,
		IpAddress:    "",
		UserAgent:    "",
	}); err != nil {
		s.log.Warn().Err(err).Str("provider", providerID).Str("account", account).Str("full_name", fullName).Str("action", action).Msg("create repository inventory audit log")
	}
}

func matchInstallationAccount(installations []forge.Installation, account string) (forge.Installation, bool) {
	for _, installation := range installations {
		if equalAccount(installation.AccountName, account) {
			return installation, true
		}
	}
	return forge.Installation{}, false
}

func equalAccount(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func normalizeRepositoryKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func repositoryAccount(account, fullName string) string {
	account = strings.TrimSpace(account)
	if account != "" {
		return account
	}
	owner, _, ok := strings.Cut(strings.TrimSpace(fullName), "/")
	if !ok {
		return account
	}
	return owner
}

func stringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
