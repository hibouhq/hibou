package server

import (
	"context"

	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

// configuredScopes is the scanners section of .hibou.yaml resolved for one
// snapshot (ADR-034 §2): how CI runs each tool when an upload declared
// nothing itself. An upload's --scope/--path and a scan plan binding win.
type configuredScopes struct {
	cfg *repoconfig.RepoConfig
	// unknown: the config could not be read (forge error). Coverage is then
	// unknown too, so undeclared runs count as partial, never as full.
	unknown bool
	// pullRequest: the snapshot is a PR build, where changed-files applies.
	pullRequest bool
	// changed lists the PR's files; changedKnown is false when the
	// comparison was unavailable, truncated or not needed.
	changed      []string
	changedKnown bool
}

// resolveConfiguredScopes reads .hibou.yaml only when a SARIF artifact of
// the snapshot declared no scope, and compares the PR only when a tool is
// configured changed-files. The comparison is the one the PR's diff and
// patch coverage use, so it is usually already cached: no extra forge call.
func (s *Server) resolveConfiguredScopes(ctx context.Context, snapshot *store.Snapshot, artifacts []store.SnapshotArtifact) *configuredScopes {
	if s.repoConfigLoader == nil || !hasUndeclaredSARIF(artifacts) {
		return nil
	}
	ref, err := s.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return &configuredScopes{unknown: true}
	}
	repo, err := s.queries.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil || repo == nil {
		return &configuredScopes{unknown: true}
	}
	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		return nil
	}
	cfg, err := s.repoConfigLoader.Load(ctx, repo.Provider, owner, name, repo.DefaultBranch)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("repo config unavailable; undeclared scanner runs count as partial")
		return &configuredScopes{unknown: true}
	}
	if cfg == nil || len(cfg.Scanners) == 0 {
		return nil
	}
	scopes := &configuredScopes{cfg: cfg}
	if !configuresChangedFiles(cfg) {
		return scopes
	}
	if ref.RefType != store.RefTypePullRequest {
		return scopes
	}
	scopes.pullRequest = true
	base := snapshot.BaseCommitSHA
	if base == "" && ref.MergeTargetRefID != nil {
		// Forge comparisons are three-dot (from the merge base), so the
		// target's tip yields the same PR files as the base CI used.
		if target, err := s.queries.GetRefByID(ctx, *ref.MergeTargetRefID); err == nil && target != nil && target.LatestCommitSHA != nil {
			base = *target.LatestCommitSHA
		}
	}
	if base == "" || base == snapshot.CommitSHA {
		return scopes
	}
	index, err := s.presenceComparison(ctx, repo, base, snapshot.CommitSHA, false)
	if err != nil || index.unsupported || index.truncated {
		return scopes
	}
	scopes.changed = make([]string, 0, len(index.files))
	for path, change := range index.files {
		if !change.Removed {
			scopes.changed = append(scopes.changed, path)
		}
	}
	scopes.changedKnown = true
	return scopes
}

func hasUndeclaredSARIF(artifacts []store.SnapshotArtifact) bool {
	for _, artifact := range artifacts {
		if artifact.Kind == "sarif" && artifact.Scope == nil {
			return true
		}
	}
	return false
}

func configuresChangedFiles(cfg *repoconfig.RepoConfig) bool {
	for _, run := range cfg.Scanners {
		if run.Scope == repoconfig.ScannerScopeChangedFiles {
			return true
		}
	}
	return false
}

// runScope returns the scope of an undeclared run of producer, and whether
// it comes from the config (declared) rather than the full-run assumption.
func (c *configuredScopes) runScope(producer string) (scope string, paths []string, declared bool) {
	if c == nil {
		return store.ProducerScopeFull, nil, false
	}
	if c.unknown {
		return store.ProducerScopePartial, nil, false
	}
	run, ok := c.cfg.ScannerRunFor(producer)
	if !ok {
		return store.ProducerScopeFull, nil, false
	}
	switch run.Scope {
	case repoconfig.ScannerScopePartial:
		return store.ProducerScopePartial, run.Paths, true
	case repoconfig.ScannerScopeChangedFiles:
		if !c.pullRequest {
			return store.ProducerScopeFull, nil, true
		}
		if !c.changedKnown {
			// Which files the PR changed is unknown: nothing absent can be
			// read as fixed, so the run covers an unknown part.
			return store.ProducerScopePartial, nil, true
		}
		return store.ProducerScopePartial, c.changed, true
	default:
		return store.ProducerScopeFull, nil, true
	}
}
