package forge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type gateReportingConfigLoader interface {
	HasGateReportingConfig(ctx context.Context, providerID, owner, repo, defaultBranch string) (bool, error)
}

// PendingGateRetirer updates existing pending checks only. It must not create
// a check on a repository that never enabled PR reporting.
type PendingGateRetirer interface {
	RetirePendingGate(ctx context.Context, owner, repo, headSHA, name string) error
}

func (a *GatePublisher) repositoryReportingEnabled(ctx context.Context, repo dbgen.Repository) (bool, error) {
	enabled, err := a.store.HasGateIntegration(ctx, repo.ID)
	if err != nil || enabled {
		return enabled, err
	}
	loader, ok := a.repoConfigLoader.(gateReportingConfigLoader)
	if !ok {
		return false, nil
	}
	owner, name, ok := repoCoordinates(repo)
	if !ok {
		return false, errors.New("repository has no forge coordinates")
	}
	return loader.HasGateReportingConfig(ctx, repo.Provider, owner, name, repo.DefaultBranch)
}

// RepositoryReportingEnabled separates monitoring enrollment from a CI upload
// integration or explicitly configured repository quality gates.
func (a *GatePublisher) RepositoryReportingEnabled(ctx context.Context, repoID uuid.UUID) (bool, error) {
	repo, err := a.store.GetRepoByID(ctx, repoID)
	if err != nil {
		return false, err
	}
	if repo.ID == uuid.Nil {
		return false, sql.ErrNoRows
	}
	return a.repositoryReportingEnabled(ctx, repo)
}

// RetireUnintegratedChecks clears old placeholders during normal PR
// reconciliation, including repositories whose gate intent was already cleared.
func (a *GatePublisher) RetireUnintegratedChecks(ctx context.Context, repoID uuid.UUID) error {
	enabled, err := a.RepositoryReportingEnabled(ctx, repoID)
	if err != nil || enabled {
		return err
	}
	refs, err := a.store.ListOpenPRRefs(ctx, repoID)
	if err != nil {
		return err
	}
	for _, row := range refs {
		ref, err := a.store.GetRefByID(ctx, row.ID)
		if err != nil {
			return err
		}
		if ref.RefType != dbgen.RefTypePullRequest || !ref.LatestCommitSha.Valid || strings.TrimSpace(ref.LatestCommitSha.String) == "" {
			continue
		}
		repo, provider, owner, name, ok := a.loadGateRepositoryIdentity(ctx, ref)
		if !ok {
			return fmt.Errorf("cannot safely retire PR check for repository %s", repoID)
		}
		if tiered, ok := provider.(interface{ Tier() Tier }); ok && tiered.Tier() == TierRead {
			a.log.Warn().Str("repo_id", repo.ID.String()).Msg("read-only forge cannot retire existing PR checks; report tier is required for cleanup")
			continue
		}
		retirer, ok := provider.(PendingGateRetirer)
		if !ok {
			return fmt.Errorf("forge %q does not support retiring pending PR checks", repo.Provider)
		}
		if err := retirer.RetirePendingGate(ctx, owner, name, ref.LatestCommitSha.String, securityStatusContext); err != nil {
			return fmt.Errorf("retire pending PR check: %w", err)
		}
	}
	return nil
}

func (a *GatePublisherStoreAdapter) HasGateIntegration(ctx context.Context, repoID uuid.UUID) (bool, error) {
	uploaded, err := a.queries.RepoHasUploadActivity(ctx, repoID)
	if err != nil || uploaded {
		return uploaded, err
	}
	gates, err := a.queries.ListQualityGatesByRepo(ctx, uuid.NullUUID{UUID: repoID, Valid: true})
	if err != nil {
		return false, err
	}
	for _, gate := range gates {
		if gate.Enabled {
			return true, nil
		}
	}
	return false, nil
}
