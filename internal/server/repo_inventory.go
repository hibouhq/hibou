package server

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

const repositoryFreshnessWindow = 30 * 24 * time.Hour

type repoLifecycleStatus string

const (
	repoLifecycleStatusArchived   repoLifecycleStatus = "archived"
	repoLifecycleStatusActive     repoLifecycleStatus = "active"
	repoLifecycleStatusDiscovered repoLifecycleStatus = "discovered"
	repoLifecycleStatusDeleted    repoLifecycleStatus = "deleted"
)

type repositoryInventoryEntry struct {
	ID            *uuid.UUID          `json:"id,omitempty"`
	OrgID         *uuid.UUID          `json:"org_id,omitempty"`
	Name          string              `json:"name"`
	Slug          string              `json:"slug"`
	Provider      string              `json:"provider"`
	ProviderID    string              `json:"provider_id"`
	DefaultBranch string              `json:"default_branch"`
	SyncState     string              `json:"sync_state,omitempty"`
	FullName      string              `json:"full_name"`
	HTMLURL       string              `json:"html_url"`
	Private       bool                `json:"private"`
	Enrolled      bool                `json:"enrolled"`
	Status        repoLifecycleStatus `json:"status"`
	LastScanned   *time.Time          `json:"last_scanned,omitempty"`
	Outdated      bool                `json:"outdated"`
}

type repoInventorySummary struct {
	TotalAccessible int `json:"total_accessible"`
	Enrolled        int `json:"enrolled"`
	Discovered      int `json:"discovered"`
	Active          int `json:"active"`
	Archived        int `json:"archived"`
	Outdated        int `json:"outdated"`
}

type repoSnapshotState struct {
	ref      *store.Ref
	snapshot *store.Snapshot
}

func (s *Server) listRepositoryInventory(r *http.Request, org *store.Organization) ([]repositoryInventoryEntry, repoInventorySummary, error) {
	forgeURL := s.forgeWebURL(org.Provider)
	enrolledRepos, err := s.listAllReposByOrg(r, org.ID)
	if err != nil {
		return nil, repoInventorySummary{}, err
	}
	inventoryRepos, err := s.queries.ListForgeRepositoriesByAccount(r.Context(), org.Provider, org.Slug)
	if err != nil {
		return nil, repoInventorySummary{}, err
	}

	repoByKey, snapshotByKey, err := s.loadEnrolledRepositoryState(r, enrolledRepos)
	if err != nil {
		return nil, repoInventorySummary{}, err
	}

	entries := make([]repositoryInventoryEntry, 0, len(inventoryRepos)+len(enrolledRepos))
	seen := make(map[string]struct{}, len(inventoryRepos)+len(enrolledRepos))
	entries = append(entries, s.inventoryBackedEntries(org, forgeURL, inventoryRepos, repoByKey, snapshotByKey, seen)...)
	entries = append(entries, s.enrolledOnlyEntries(org, forgeURL, enrolledRepos, snapshotByKey, seen)...)

	sort.SliceStable(entries, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(entries[i].FullName))
		right := strings.ToLower(strings.TrimSpace(entries[j].FullName))
		if left == right {
			return strings.ToLower(strings.TrimSpace(entries[i].Name)) < strings.ToLower(strings.TrimSpace(entries[j].Name))
		}
		return left < right
	})

	return entries, summarizeRepositoryInventory(entries), nil
}

func (s *Server) loadEnrolledRepositoryState(r *http.Request, enrolledRepos []store.Repository) (map[string]store.Repository, map[string]repoSnapshotState, error) {
	repoByKey := make(map[string]store.Repository, len(enrolledRepos))
	snapshotByKey := make(map[string]repoSnapshotState, len(enrolledRepos))
	for _, repo := range enrolledRepos {
		key := repositoryInventoryKeyForRepo(repo)
		repoByKey[key] = repo

		ref, snapshot, err := s.resolveSnapshotForRepo(r, &repo, repo.DefaultBranch)
		if err != nil {
			return nil, nil, err
		}
		snapshotByKey[key] = repoSnapshotState{ref: ref, snapshot: snapshot}
	}
	return repoByKey, snapshotByKey, nil
}

func (s *Server) inventoryBackedEntries(org *store.Organization, forgeURL string, inventoryRepos []store.ForgeRepository, repoByKey map[string]store.Repository, snapshotByKey map[string]repoSnapshotState, seen map[string]struct{}) []repositoryInventoryEntry {
	entries := make([]repositoryInventoryEntry, 0, len(inventoryRepos))
	for _, inventoryRepo := range inventoryRepos {
		key := normalizeInventoryRepoKey(inventoryRepo.ProviderKey)
		repo, hasRepo := repoByKey[key]
		var repoPtr *store.Repository
		if hasRepo {
			repoPtr = &repo
		}
		entries = append(entries, buildRepositoryInventoryEntry(org, forgeURL, repoPtr, &inventoryRepo, snapshotByKey[key]))
		seen[key] = struct{}{}
	}
	return entries
}

func (s *Server) enrolledOnlyEntries(org *store.Organization, forgeURL string, enrolledRepos []store.Repository, snapshotByKey map[string]repoSnapshotState, seen map[string]struct{}) []repositoryInventoryEntry {
	entries := make([]repositoryInventoryEntry, 0, len(enrolledRepos))
	for _, repo := range enrolledRepos {
		key := repositoryInventoryKeyForRepo(repo)
		if _, ok := seen[key]; ok {
			continue
		}
		entries = append(entries, buildRepositoryInventoryEntry(org, forgeURL, &repo, nil, snapshotByKey[key]))
	}
	return entries
}

func buildRepositoryInventoryEntry(org *store.Organization, forgeURL string, repo *store.Repository, inventoryRepo *store.ForgeRepository, snapshotState repoSnapshotState) repositoryInventoryEntry {
	entry := repositoryInventoryEntry{}
	if repo != nil {
		entry.ID = &repo.ID
		entry.OrgID = &repo.OrgID
		entry.Name = repo.Name
		entry.Slug = repo.Slug
		entry.Provider = repo.Provider
		entry.ProviderID = repo.ProviderID
		entry.DefaultBranch = repo.DefaultBranch
		entry.SyncState = repo.SyncState
		entry.Enrolled = true
	}
	if inventoryRepo != nil {
		if entry.Name == "" {
			entry.Name = inventoryRepo.Name
		}
		if entry.Provider == "" {
			entry.Provider = inventoryRepo.Provider
		}
		if entry.ProviderID == "" {
			entry.ProviderID = inventoryRepo.FullName
		}
		if entry.DefaultBranch == "" {
			entry.DefaultBranch = inventoryRepo.DefaultBranch
		}
		entry.FullName = inventoryRepo.FullName
		entry.HTMLURL = inventoryRepo.HTMLURL
		entry.Private = inventoryRepo.Private
	}
	if entry.FullName == "" {
		entry.FullName = entry.ProviderID
	}
	if entry.HTMLURL == "" {
		entry.HTMLURL = forgeRepoURL(org, forgeURL, entry.Provider, entry.ProviderID)
	}
	if entry.DefaultBranch == "" {
		entry.DefaultBranch = "main"
	}
	entry.Status = classifyRepositoryLifecycle(inventoryRepo, snapshotState)
	if snapshotState.snapshot != nil {
		lastScanned := snapshotState.snapshot.CreatedAt
		entry.LastScanned = &lastScanned
		entry.Outdated = !repositorySnapshotCurrent(snapshotState.ref, snapshotState.snapshot)
	}
	return entry
}

func summarizeRepositoryInventory(entries []repositoryInventoryEntry) repoInventorySummary {
	summary := repoInventorySummary{TotalAccessible: len(entries)}
	for _, entry := range entries {
		if entry.Enrolled {
			summary.Enrolled++
		}
		switch entry.Status {
		case repoLifecycleStatusArchived:
			summary.Archived++
		case repoLifecycleStatusActive:
			summary.Active++
		case repoLifecycleStatusDiscovered:
			summary.Discovered++
		}
		if entry.Outdated {
			summary.Outdated++
		}
	}
	return summary
}

func classifyRepositoryLifecycle(inventoryRepo *store.ForgeRepository, snapshotState repoSnapshotState) repoLifecycleStatus {
	if inventoryRepo != nil && inventoryRepo.Archived {
		return repoLifecycleStatusArchived
	}
	if snapshotState.snapshot == nil {
		return repoLifecycleStatusDiscovered
	}
	return repoLifecycleStatusActive
}

func repositorySnapshotCurrent(ref *store.Ref, snapshot *store.Snapshot) bool {
	if snapshot == nil {
		return false
	}
	if ref != nil && ref.LatestCommitSHA != nil {
		latestCommit := strings.TrimSpace(*ref.LatestCommitSHA)
		if latestCommit != "" && !strings.EqualFold(latestCommit, strings.TrimSpace(snapshot.CommitSHA)) {
			return false
		}
	}
	return snapshot.CreatedAt.After(time.Now().UTC().Add(-repositoryFreshnessWindow))
}

func normalizeInventoryRepoKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func repositoryInventoryKeyForRepo(repo store.Repository) string {
	key := normalizeInventoryRepoKey(repo.ProviderID)
	if key != "" {
		return key
	}
	return repo.ID.String()
}

func forgeRepoURL(org *store.Organization, forgeURL, provider, providerID string) string {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return ""
	}
	if strings.TrimSpace(forgeURL) != "" {
		return strings.TrimRight(strings.TrimSpace(forgeURL), "/") + "/" + providerID
	}
	provider = strings.TrimSpace(provider)
	if provider == "" && org != nil {
		provider = org.Provider
	}
	var base string
	switch provider {
	case "github":
		base = "https://github.com"
	case "gitlab":
		base = "https://gitlab.com"
	case "forgejo":
		base = ""
	}
	if base == "" {
		return ""
	}
	return base + "/" + providerID
}
