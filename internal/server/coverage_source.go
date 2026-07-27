package server

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type coverageSourceLine struct {
	Number int `json:"number"`
	Hits   int `json:"hits"`
}

type coverageSourceResponse struct {
	Path      string               `json:"path"`
	CommitSHA string               `json:"commit_sha"`
	Content   string               `json:"content"`
	Lines     []coverageSourceLine `json:"lines"`
}

// @Summary      Annotated source for a covered file
// @Description  Streams the file blob at the snapshot's commit from the forge together with its per-line hit counts. Source is never stored; the forge token stays server-side.
// @Tags         coverage
// @Produce      json
// @Param        provider    path      string  true   "Forge provider"
// @Param        slug        path      string  true   "Organization slug"
// @Param        repoSlug    path      string  true   "Repository slug"
// @Param        snapshotID  path      string  true   "Snapshot ID"
// @Param        path        query     string  true   "Canonical repo-root-relative file path"
// @Success      200  {object}  api.Response{data=server.coverageSourceResponse}
// @Failure      400  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      422  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/snapshots/{snapshotID}/coverage-source [get]
func (s *Server) handleGetCoverageSource(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	snapshot, status, message := s.loadSnapshotForRepoByID(r, repo, chi.URLParam(r, "snapshotID"))
	if status != 0 {
		api.JSONError(w, status, message)
		return
	}

	requested := strings.Trim(strings.TrimSpace(r.URL.Query().Get("path")), "/")
	if requested == "" || strings.Contains(requested, "..") {
		api.JSONError(w, http.StatusBadRequest, "path query parameter is required")
		return
	}

	provider := s.forges[repo.Provider]
	if provider == nil {
		api.JSONError(w, http.StatusUnprocessableEntity, "no forge provider configured for this repository")
		return
	}
	owner, name, ok := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !ok {
		api.JSONError(w, http.StatusUnprocessableEntity, "repository has no owner/name coordinates")
		return
	}

	resolved, content, err := s.resolveSourceBlob(r, provider, owner, name, snapshot, requested)
	if errors.Is(err, forge.ErrFileNotFound) {
		api.JSONError(w, http.StatusNotFound, "file not found at the snapshot commit")
		return
	}
	if err != nil {
		s.log.Error().Err(err).Str("repo", repo.Slug).Str("path", requested).Msg("fetch source from forge")
		api.JSONError(w, http.StatusBadGateway, "failed to fetch source from the forge")
		return
	}
	if !utf8.Valid(content) {
		api.JSONError(w, http.StatusUnprocessableEntity, "file is not text")
		return
	}

	lines, err := s.coverageLinesForPath(r, repo.Slug, snapshot.ID, requested)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load coverage lines")
		return
	}

	api.JSON(w, http.StatusOK, coverageSourceResponse{
		Path:      resolved,
		CommitSHA: snapshot.CommitSHA,
		Content:   string(content),
		Lines:     lines,
	})
}

// resolveSourceBlob fetches the file, working around two realities of
// tool-emitted paths and CI SHAs:
//
//   - Coverage paths can be rooted below the repo (ts/src → src, Java package
//     roots), so a miss retries after suffix-resolving the path against the
//     repository tree.
//   - PR snapshots record the synthetic merge commit GitHub builds for CI; a
//     rebase or re-run garbage-collects it, so a dead SHA falls back to the
//     snapshot's ref name (refs/pull/N/head stays alive as long as the PR).
func (s *Server) resolveSourceBlob(r *http.Request, provider forge.Provider, owner, name string, snapshot *store.Snapshot, requested string) (string, []byte, error) {
	refs := []string{snapshot.CommitSHA}
	if fallback := s.snapshotFallbackRef(r, snapshot); fallback != "" {
		refs = append(refs, fallback)
	}

	for i, ref := range refs {
		content, err := provider.GetFileContent(r.Context(), owner, name, requested, ref)
		if err == nil {
			return requested, content, nil
		}
		if !errors.Is(err, forge.ErrFileNotFound) {
			return "", nil, err
		}

		paths, treeErr := provider.ListTreePaths(r.Context(), owner, name, ref)
		if errors.Is(treeErr, forge.ErrFileNotFound) {
			continue // dead SHA: the whole ref is gone, try the fallback
		}
		if treeErr != nil {
			return "", nil, treeErr
		}
		resolved := resolveTreePath(paths, requested)
		if resolved == "" {
			if i < len(refs)-1 {
				continue
			}
			return "", nil, forge.ErrFileNotFound
		}
		content, err = provider.GetFileContent(r.Context(), owner, name, resolved, ref)
		if err == nil {
			return resolved, content, nil
		}
		if !errors.Is(err, forge.ErrFileNotFound) {
			return "", nil, err
		}
	}
	return "", nil, forge.ErrFileNotFound
}

// snapshotFallbackRef returns a live ref name for the snapshot's ref row.
func (s *Server) snapshotFallbackRef(r *http.Request, snapshot *store.Snapshot) string {
	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil || ref == nil {
		return ""
	}
	if ref.RefType == store.RefTypePullRequest {
		if ref.PrNumber != nil && *ref.PrNumber != "" {
			return "refs/pull/" + *ref.PrNumber + "/head"
		}
		return ""
	}
	return ref.Name
}

// resolveTreePath finds the repository path a tool-emitted path refers to: the
// candidate that equals it, or failing that the unique-ish suffix match with
// the fewest extra leading segments (ts/src/calc.ts for src/calc.ts, the Java
// source root for a package path).
func resolveTreePath(paths []string, requested string) string {
	suffix := "/" + requested
	best := ""
	bestDepth := -1
	for _, candidate := range paths {
		if candidate == requested {
			return candidate
		}
		if !strings.HasSuffix(candidate, suffix) {
			continue
		}
		depth := strings.Count(candidate, "/")
		if bestDepth == -1 || depth < bestDepth || (depth == bestDepth && candidate < best) {
			best = candidate
			bestDepth = depth
		}
	}
	return best
}

// coverageLinesForPath merges per-line hits from every report whose file
// canonicalizes to the requested path, max-hits-wins on collisions.
func (s *Server) coverageLinesForPath(r *http.Request, repoSlug string, snapshotID uuid.UUID, canonical string) ([]coverageSourceLine, error) {
	stored, err := s.queries.ListCoverageLinesBySnapshotPath(r.Context(), snapshotID, canonical)
	if err != nil {
		return nil, err
	}
	best := map[int]int{}
	for _, line := range stored {
		if canonicalCoveragePath(line.FilePath, repoSlug) != canonical && line.FilePath != canonical {
			continue
		}
		if hits, seen := best[line.LineNumber]; !seen || line.Hits > hits {
			best[line.LineNumber] = line.Hits
		}
	}
	lines := make([]coverageSourceLine, 0, len(best))
	for number, hits := range best {
		lines = append(lines, coverageSourceLine{Number: number, Hits: hits})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Number < lines[j].Number })
	return lines, nil
}
