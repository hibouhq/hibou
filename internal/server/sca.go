package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
)

type scaCoverage struct {
	State              string     `json:"state"`
	HasInventory       bool       `json:"has_inventory"`
	Detail             string     `json:"detail,omitempty"`
	CommitSHA          string     `json:"commit_sha,omitempty"`
	LastAssessed       *time.Time `json:"last_assessed,omitempty"`
	LastAttempt        *time.Time `json:"last_attempt,omitempty"`
	JobID              *uuid.UUID `json:"job_id,omitempty"`
	Enabled            bool       `json:"enabled"`
	OnPush             bool       `json:"on_push"`
	InventorySource    string     `json:"inventory_source"`
	InventoryCommitSHA string     `json:"inventory_commit_sha,omitempty"`
	HeadCommitSHA      string     `json:"head_commit_sha,omitempty"`
	PreviousResults    bool       `json:"previous_results"`
	InventorySources   []string   `json:"inventory_sources,omitempty"`
}

func (s *Server) scaCoverage(enrolled bool, o store.SCAObservation) scaCoverage {
	currentSnapshot := o.HeadCommit == "" || o.CommitSHA == o.HeadCommit
	c := scaCoverage{
		State: "not_assessed", Enabled: s.cfg.DepInventory.Enabled, OnPush: s.cfg.DepInventory.OnPush,
		HasInventory: currentSnapshot && (o.HasInventory || o.HasComponents),
		CommitSHA:    o.CommitSHA, LastAssessed: o.LastAssessed, LastAttempt: o.LastAttempt, JobID: o.JobID,
		InventorySource: o.InventorySource, InventoryCommitSHA: o.InventoryCommit, HeadCommitSHA: o.HeadCommit,
		InventorySources: o.InventorySources,
		PreviousResults: o.PreviousInventory && (!currentSnapshot || !o.HasInventory && !o.HasComponents) ||
			!currentSnapshot && (o.HasInventory || o.HasComponents),
	}
	if c.InventorySource == "" {
		c.InventorySource = "none"
		if c.HasInventory || c.PreviousResults {
			c.InventorySource = "unknown"
		}
	}
	if len(c.InventorySources) == 0 && c.InventorySource != "none" && c.InventorySource != "mixed" {
		c.InventorySources = []string{c.InventorySource}
	}
	if c.LastAssessed == nil && c.PreviousResults {
		c.LastAssessed = o.PreviousAssessed
	}
	if !enrolled {
		c.State = "not_monitored"
		if !c.Enabled {
			c.State = "disabled"
		}
		return c
	}
	if !c.Enabled && !c.HasInventory && !c.PreviousResults {
		c.State, c.Detail = "disabled", "Dependency extraction is disabled on this instance."
		return c
	}
	jobCurrent := o.HeadCommit == "" || o.JobCommit == "" || o.JobCommit == o.HeadCommit
	newerAssessment := currentSnapshot && o.HasInventory && o.LastAssessed != nil &&
		(o.LastAttempt == nil || o.LastAssessed.After(*o.LastAttempt))
	if jobCurrent && c.Enabled {
		switch o.JobStatus {
		case "pending":
			c.State = "queued"
			return c
		case "processing":
			c.State = "extracting"
			return c
		case "failed":
			if !newerAssessment {
				c.State, c.Detail = "failed", o.JobError
				return c
			}
		}
	}
	if c.PreviousResults && !c.HasInventory || o.HeadCommit != "" && o.CommitSHA != o.HeadCommit {
		c.State = "outdated"
		c.Detail = "A newer commit is available. The listed results belong to the previous inventory."
		if !c.PreviousResults {
			c.State = "not_assessed"
			c.Detail = "The current commit has no dependency inventory yet."
		}
		return c
	}
	if o.ProducerOutcome == "failed" && !newerAssessment {
		c.State, c.Detail = "failed", o.Detail
		return c
	}
	if !o.HasInventory && !o.HasComponents {
		switch {
		case strings.HasPrefix(o.Detail, "no lockfile or manifest recognised"):
			c.State, c.Detail = "unsupported", o.Detail
		case o.ProducerOutcome == "partial":
			c.State, c.Detail = "partial", o.Detail
		case !c.Enabled:
			c.State, c.Detail = "disabled", "Dependency extraction is disabled on this instance."
		}
		return c
	}
	switch o.ScanStatus {
	case "pending", "running":
		c.State = "matching"
	case "failed":
		c.State, c.Detail = "failed", o.ScanError
	case "complete":
		c.State = "complete"
		if o.ProducerOutcome == "partial" || o.ProviderFailed {
			c.State, c.Detail = "partial", o.Detail
			if o.ProviderFailed {
				c.Detail = "One or more advisory providers failed; advisory coverage is incomplete."
			}
		}
	default:
		c.State = "inventory_ready"
		c.Detail = "Inventory is available. No completed Hibou advisory refresh is recorded for this snapshot."
		if !o.HasComponents && o.ProducerOutcome == string(store.ProducerOutcomeCompleted) {
			c.State, c.Detail = "complete", "Dependency extraction completed with no components to match against advisories."
		} else if !o.HasComponents && o.ProducerOutcome == string(store.ProducerOutcomePartial) {
			c.State, c.Detail = "partial", o.Detail
		}
		if o.HasReportedFindings {
			c.State = "reported"
			c.Detail = "Dependency findings were reported for this snapshot. No completed Hibou advisory refresh is recorded."
		}
	}
	return c
}

type enableSCAResult struct {
	ProviderID string     `json:"provider_id"`
	RepoSlug   string     `json:"repo_slug,omitempty"`
	JobID      *uuid.UUID `json:"job_id,omitempty"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
}

// handleEnableSCA accepts only inventory keys, never clone URLs or identity
// metadata supplied by the caller.
func (s *Server) handleEnableSCA(w http.ResponseWriter, r *http.Request) {
	user, org, ok := s.loadAdminOrgForEnrollment(w, r)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	if !s.cfg.DepInventory.Enabled {
		api.JSONError(w, http.StatusConflict, "dependency inventory extraction is disabled on this instance")
		return
	}
	if _, configured := s.forges[org.Provider]; !configured {
		api.JSONError(w, http.StatusServiceUnavailable, "this organization's forge provider is not configured")
		return
	}
	var input struct {
		ProviderIDs []string `json:"provider_ids"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || len(input.ProviderIDs) == 0 || len(input.ProviderIDs) > 50 {
		api.JSONError(w, http.StatusBadRequest, "provide between 1 and 50 repository inventory keys")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		api.JSONError(w, http.StatusBadRequest, "request body must contain one JSON object")
		return
	}
	for _, id := range input.ProviderIDs {
		if strings.TrimSpace(id) == "" || len(id) > 512 {
			api.JSONError(w, http.StatusBadRequest, "invalid repository inventory key")
			return
		}
	}
	results := make([]enableSCAResult, 0, len(input.ProviderIDs))
	seen := make(map[string]enableSCAResult, len(input.ProviderIDs))
	for _, id := range input.ProviderIDs {
		key := normalizeInventoryRepoKey(id)
		if result, exists := seen[key]; exists {
			results = append(results, result)
			continue
		}
		result, repo, created, err := s.enableSCA(r.Context(), org, strings.TrimSpace(id))
		if err != nil {
			s.log.Error().Err(err).Str("org_id", org.ID.String()).Str("provider_id", id).Msg("enable repository SCA")
			result = enableSCAResult{ProviderID: id, Status: "failed", Error: "Could not enable SCA. Verify current forge access and repository identity, then retry."}
			var public *scaEnableError
			if errors.As(err, &public) {
				result.Error = public.Error()
			}
		} else if created {
			s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionRepoEnrolled, map[string]any{
				"name": repo.Name, "slug": repo.Slug, "source": "sca",
			})
		}
		seen[key] = result
		results = append(results, result)
	}
	api.JSON(w, http.StatusAccepted, struct {
		Results []enableSCAResult `json:"results"`
	}{results})
}

type scaEnableError struct{ message string }

func (e *scaEnableError) Error() string { return e.message }

func (s *Server) enableSCA(ctx context.Context, org *store.Organization, providerID string) (enableSCAResult, *store.Repository, bool, error) {
	if err := s.refreshSCAInventoryMetadata(ctx, org, providerID); err != nil {
		return enableSCAResult{}, nil, false, err
	}
	// A CI upload can race enrollment without taking the org lock. Retry its
	// unique-constraint race in a fresh transaction, adopting its repository.
	for attempt := 0; attempt < 2; attempt++ {
		result, repo, created, err := s.enableSCATransaction(ctx, org, providerID)
		if !isUniqueViolation(err) {
			return result, repo, created, err
		}
	}
	return enableSCAResult{}, nil, false, errors.New("concurrent repository enrollment; retry enablement")
}

func (s *Server) enableSCATransaction(ctx context.Context, org *store.Organization, providerID string) (enableSCAResult, *store.Repository, bool, error) {
	result := enableSCAResult{ProviderID: providerID, Status: "accepted"}
	tx, err := s.queries.BeginTx(ctx)
	if err != nil {
		return result, nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	// Serializes enablement and slug allocation within this organization.
	if _, err := tx.ExecContext(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, org.ID); err != nil {
		return result, nil, false, err
	}
	inv, err := q.LockSCAInventory(ctx, org.ID, providerID)
	if err != nil {
		return result, nil, false, err
	}
	if inv == nil {
		return result, nil, false, &scaEnableError{"Repository is not in this organization's current verified forge inventory. Sync repositories and retry."}
	}
	if inv.Archived {
		return result, nil, false, &scaEnableError{"Archived repositories cannot enable automatic SCA. Unarchive the repository on the forge first."}
	}
	if strings.TrimSpace(inv.DefaultBranch) == "" {
		return result, nil, false, &scaEnableError{"Repository has no default branch to extract."}
	}
	repo, err := q.GetRepositoryByProviderID(ctx, org.ID, org.Provider, inv.ProviderKey)
	if err != nil {
		return result, nil, false, err
	}
	created := repo == nil
	if created {
		slug := store.SlugifyForgeAccount(inv.Name)
		if len(slug) > 54 {
			slug = strings.TrimRight(slug[:54], "-")
		}
		if !api.IsValidSlug(slug) {
			slug = "repo-" + slug
		}
		existing, err := q.GetRepositoryBySlug(ctx, org.ID, slug)
		if err != nil {
			return result, nil, false, err
		}
		if existing != nil {
			sum := sha256.Sum256([]byte(inv.ProviderKey))
			slug += "-" + hex.EncodeToString(sum[:4])
		}
		repo, err = q.CreateRepository(ctx, org.ID, nil, inv.Name, slug, org.Provider, inv.ProviderKey, inv.DefaultBranch, "enrolled")
		if err != nil {
			return result, nil, false, err
		}
	}
	if _, err := q.VerifiedForgeRepositoryTarget(ctx, repo.ID); err != nil {
		return result, nil, false, err
	}
	refName := normalizeStoredRefName(repo.DefaultBranch)
	ref, err := q.GetRefByRepoAndName(ctx, repo.ID, refName, store.RefTypeBranch)
	if err != nil {
		return result, nil, false, err
	}
	commit := ""
	if ref != nil && ref.LatestCommitSHA != nil {
		commit = *ref.LatestCommitSHA
	}
	job, queued, err := q.EnqueueSCAExtraction(ctx, store.EnqueueDepExtractionJobParams{
		RepoID: repo.ID, RefName: refName, CommitSHA: commit, Reason: store.DepExtractionReasonEnableSCA,
	})
	if err != nil {
		return result, nil, false, err
	}
	if !queued {
		result.Status = "existing"
	}
	result.RepoSlug, result.JobID = repo.Slug, &job.ID
	if err := tx.Commit(); err != nil {
		return result, nil, false, err
	}
	return result, repo, created, nil
}

func (s *Server) runSCABootstrapLoop(ctx context.Context) {
	run := func() {
		if !s.cfg.DepInventory.Enabled {
			return
		}
		passCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := store.WithLeaderLock(passCtx, s.db, "hibou:sca-bootstrap", func(ctx context.Context) error {
			count, err := s.queries.BootstrapSCA(ctx, uuid.Nil, 100)
			if err == nil && count > 0 {
				s.log.Info().Int64("queued", count).Msg("bootstrapped dependency inventory")
			}
			return err
		}); err != nil && ctx.Err() == nil {
			s.log.Error().Err(err).Msg("SCA bootstrap reconciliation failed")
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) dependencyCoverageForRepo(ctx context.Context, repo *store.Repository, refName string) (scaCoverage, error) {
	observations, err := s.queries.ListSCAObservations(ctx, repo.OrgID, repo.ID, normalizeStoredRefName(refName), refTypeFromName(refName))
	if err != nil {
		return scaCoverage{}, fmt.Errorf("load dependency coverage: %w", err)
	}
	return s.scaCoverage(true, observations[repo.ID]), nil
}
