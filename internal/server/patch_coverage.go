package server

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/comparison"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

// applyNewCodeLens annotates the coverage diff with new-code stats (ADR-019):
// which of the comparison's changed lines are instrumented and covered. Works
// for any base..head pair, not just PRs, and no-ops when the forge cannot
// classify — the classic view stays correct.
func (s *Server) applyNewCodeLens(ctx context.Context, repo *store.Repository, coverageDiff *comparison.CoverageDiff, baseSnapshot, headSnapshot *store.Snapshot, cfg *repoconfig.RepoConfig) {
	if coverageDiff == nil || repo == nil || baseSnapshot == nil || headSnapshot == nil {
		return
	}
	provider := s.forges[repo.Provider]
	patch := s.changedLinesForComparison(ctx, repo, provider, baseSnapshot.CommitSHA, headSnapshot.CommitSHA)
	if patch == nil {
		return
	}

	headLines, err := s.loadSnapshotCoverageLines(ctx, headSnapshot.ID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", headSnapshot.ID.String()).Msg("load per-line coverage for the new-code lens")
		return
	}

	changed := make(map[string][]int, len(patch.Files))
	for _, file := range patch.Files {
		if len(file.AddedLines) > 0 {
			changed[file.Path] = file.AddedLines
		}
	}
	comparison.ApplyNewCodeLens(coverageDiff, changed, headLines, coverageExcludeGlobs(cfg), patch.Truncated)
}

// buildPatchCoverage computes line-level patch (diff) coverage for a pull
// request comparison: it fetches the forge diff between the base and head
// commits, loads both snapshots' per-line hits across every report, honors
// coverage.exclude, and intersects the two. It degrades gracefully to nil —
// letting the UI fall back to the file-level coverage diff — when the forge
// has no patch support, the diff/commit info is missing, or an API call fails.
func (s *Server) buildPatchCoverage(ctx context.Context, repo *store.Repository, baseSnapshot, headSnapshot *store.Snapshot, cfg *repoconfig.RepoConfig) *comparison.PatchCoverage {
	provider := s.forges[repo.Provider]
	if provider == nil {
		return nil
	}
	if baseSnapshot.CommitSHA == "" || headSnapshot.CommitSHA == "" {
		return nil
	}

	// Shared with the new-code lens (ADR-019) and cached per immutable SHA pair,
	// so the compare page pays at most one forge round-trip per comparison.
	patch := s.changedLinesForComparison(ctx, repo, provider, baseSnapshot.CommitSHA, headSnapshot.CommitSHA)
	if patch == nil || len(patch.Files) == 0 {
		return nil
	}

	headLines, err := s.loadSnapshotCoverageLines(ctx, headSnapshot.ID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", headSnapshot.ID.String()).Msg("failed to load per-line coverage for patch coverage")
		return nil
	}
	if len(headLines) == 0 {
		return nil
	}
	baseLines, err := s.loadSnapshotCoverageLines(ctx, baseSnapshot.ID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", baseSnapshot.ID.String()).Msg("failed to load base per-line coverage; gained/lost tinting degrades")
		baseLines = nil
	}

	changes := make([]comparison.PatchChange, 0, len(patch.Files))
	for _, file := range patch.Files {
		changes = append(changes, comparison.PatchChange{
			FilePath:   file.Path,
			AddedLines: file.AddedLines,
			Hunks:      file.Hunks,
		})
	}

	return comparison.BuildPatchCoverage(changes, headLines, baseLines, coverageExcludeGlobs(cfg), patch.Truncated)
}

// loadSnapshotCoverageLines returns a snapshot's per-line hits keyed by file
// path, across every coverage report so multi-language changes are all
// measurable (a single "primary" report dropped every other language).
func (s *Server) loadSnapshotCoverageLines(ctx context.Context, snapshotID uuid.UUID) (map[string][]comparison.PatchLine, error) {
	lines, err := s.queries.ListCoverageLinesBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string][]comparison.PatchLine)
	for _, line := range lines {
		byPath[line.FilePath] = append(byPath[line.FilePath], comparison.PatchLine{
			Number: line.LineNumber,
			Hits:   line.Hits,
		})
	}
	return byPath, nil
}

// loadCompareRepoConfig best-effort loads the repo's .hibou.yaml for a compare
// request. Returns nil (callers degrade) when unavailable.
func (s *Server) loadCompareRepoConfig(ctx context.Context, repo *store.Repository) *repoconfig.RepoConfig {
	if s.repoConfigLoader == nil {
		return nil
	}
	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		return nil
	}
	cfg, err := s.repoConfigLoader.Load(ctx, repo.Provider, owner, name, repo.DefaultBranch)
	if err != nil {
		s.log.Warn().Err(err).Str("provider", repo.Provider).Str("owner", owner).Str("repo", name).
			Msg("failed to load repo config for compare; patch coverage gate skipped")
		return nil
	}
	return cfg
}

func coverageExcludeGlobs(cfg *repoconfig.RepoConfig) []string {
	if cfg == nil || cfg.Coverage == nil {
		return nil
	}
	return cfg.Coverage.Exclude
}

func coverageGateConfigured(cfg *repoconfig.RepoConfig, targetBranch string) bool {
	if cfg == nil {
		return false
	}
	gate := cfg.MatchGate(targetBranch)
	return gate != nil && gate.Coverage != nil
}

// evaluateCoverageGate applies the branch-matched coverage thresholds from
// .hibou.yaml (min_coverage, grace, diff_minimum) against the coverage diff and
// patch coverage, returning a human-readable reason per failing threshold.
// Thresholds are percentages (0..100); coverage rates are 0..1 fractions.
func evaluateCoverageGate(cfg *repoconfig.RepoConfig, targetBranch string, coverageDiff *comparison.CoverageDiff, patch *comparison.PatchCoverage) []string {
	if cfg == nil {
		return nil
	}
	gate := cfg.MatchGate(targetBranch)
	if gate == nil || gate.Coverage == nil {
		return nil
	}
	thresholds := gate.Coverage
	reasons := make([]string, 0, 3)

	headRate, hasHead := headLineRate(coverageDiff)
	if thresholds.MinCoverage != nil && hasHead && headRate*100 < *thresholds.MinCoverage {
		reasons = append(reasons, fmt.Sprintf("coverage %.2f%% is below the minimum %.2f%%", headRate*100, *thresholds.MinCoverage))
	}

	if thresholds.Grace != nil {
		if baseRate, hasBase := baseLineRate(coverageDiff); hasBase && hasHead {
			drop := (baseRate - headRate) * 100
			if drop > *thresholds.Grace {
				reasons = append(reasons, fmt.Sprintf("coverage dropped %.2f%% versus the target branch, beyond the allowed %.2f%%", drop, *thresholds.Grace))
			}
		}
	}

	if thresholds.DiffMinimum != nil && patch != nil && patch.Rate != nil && *patch.Rate*100 < *thresholds.DiffMinimum {
		reasons = append(reasons, fmt.Sprintf("patch coverage %.2f%% is below the minimum %.2f%% on changed lines", *patch.Rate*100, *thresholds.DiffMinimum))
	}

	return reasons
}

func headLineRate(diff *comparison.CoverageDiff) (float64, bool) {
	if diff == nil || diff.Head == nil || diff.Head.LineRate == nil {
		return 0, false
	}
	return *diff.Head.LineRate, true
}

func baseLineRate(diff *comparison.CoverageDiff) (float64, bool) {
	if diff == nil || diff.Base == nil || diff.Base.LineRate == nil {
		return 0, false
	}
	return *diff.Base.LineRate, true
}
