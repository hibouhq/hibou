package server

import (
	"context"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// changedLinesForComparison returns the forge's changed-line classification for
// base..head — the definition of "new code" in ADR-019 — served from
// compare_patch_cache when possible.
//
// Both SHAs are immutable, so a cached entry can never go stale: the first view
// of a comparison pays one forge round-trip, every later view is a cache hit.
// Returns nil when the provider cannot compare (GitLab/Forgejo stubs) so callers
// degrade to the classic view rather than erroring.
func (s *Server) changedLinesForComparison(ctx context.Context, repo *store.Repository, provider forge.Provider, baseSHA, headSHA string) *forge.PatchDiff {
	if repo == nil || provider == nil || baseSHA == "" || headSHA == "" || baseSHA == headSHA {
		return nil
	}

	if cached, err := s.queries.GetComparePatchCache(ctx, repo.ID, baseSHA, headSHA); err != nil {
		s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Msg("read compare patch cache")
	} else if cached != nil {
		return patchDiffFromCache(cached)
	}

	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		return nil
	}
	patch, err := provider.ComparePatch(ctx, owner, name, baseSHA, headSHA)
	if err != nil {
		s.log.Warn().Err(err).Str("provider", repo.Provider).Str("owner", owner).Str("repo", name).
			Msg("fetch forge comparison for new-code classification")
		return nil
	}
	if patch == nil {
		return nil
	}

	// Cache even an empty file list: "this comparison changed nothing
	// measurable" is a real answer worth not re-asking.
	if err := s.queries.UpsertComparePatchCache(ctx, repo.ID, baseSHA, headSHA, cacheEntryFromPatchDiff(patch)); err != nil {
		s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Msg("write compare patch cache")
	}
	return patch
}

// patchDiffFromCache rebuilds the provider shape from a cache row, hunks
// included: the annotated PR diff renders from them, so a hit without hunks
// would blank every diff view.
func patchDiffFromCache(entry *store.ComparePatchCacheEntry) *forge.PatchDiff {
	files := make([]forge.PatchFile, 0, len(entry.Files))
	for _, file := range entry.Files {
		files = append(files, forge.PatchFile{
			Path:       file.Path,
			OldPath:    file.OldPath,
			Status:     file.Status,
			AddedLines: file.AddedLines,
			Hunks:      file.Hunks,
		})
	}
	return &forge.PatchDiff{Files: files, Truncated: entry.Truncated}
}

func cacheEntryFromPatchDiff(patch *forge.PatchDiff) store.ComparePatchCacheEntry {
	files := make([]store.ComparePatchCachedFile, 0, len(patch.Files))
	for _, file := range patch.Files {
		files = append(files, store.ComparePatchCachedFile{
			Path:       file.Path,
			OldPath:    file.OldPath,
			Status:     file.Status,
			AddedLines: file.AddedLines,
			Hunks:      file.Hunks,
		})
	}
	return store.ComparePatchCacheEntry{Truncated: patch.Truncated, Files: files}
}
