package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
)

type createReleaseRequest struct {
	Version       string          `json:"version"`
	Ref           string          `json:"ref"`
	SnapshotID    *string         `json:"snapshot_id"`
	BuildMetadata json.RawMessage `json:"build_metadata"`
	ArtifactIDs   json.RawMessage `json:"artifact_ids"`
	Provenance    json.RawMessage `json:"provenance"`
	PublishedAt   *time.Time      `json:"published_at"`
}

// @Summary      Create release
// @Description  Create a release for a repository when the caller is an organization admin
// @Tags         releases
// @Accept       json
// @Produce      json
// @Param        provider  path      string                true  "Forge provider"
// @Param        slug      path      string                true  "Organization slug"
// @Param        repoSlug  path      string                true  "Repository slug"
// @Param        body      body      createReleaseRequest  true  "Release details"
// @Success      201       {object}  api.Response{data=store.Release}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/releases [post]
func (s *Server) handleCreateRelease(w http.ResponseWriter, r *http.Request) {
	_, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}

	var input createReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Version = strings.TrimSpace(input.Version)
	input.Ref = strings.TrimSpace(input.Ref)
	if input.Version == "" {
		api.JSONError(w, http.StatusBadRequest, "version is required")
		return
	}
	if input.Ref == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return
	}

	ref, err := s.resolveRefForRepo(r, repo, input.Ref)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load reference")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "ref not found")
		return
	}

	var snapshotID *uuid.UUID
	if input.SnapshotID != nil && strings.TrimSpace(*input.SnapshotID) != "" {
		parsed, err := uuid.Parse(strings.TrimSpace(*input.SnapshotID))
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid snapshot_id")
			return
		}
		snapshot, err := s.queries.GetSnapshotByID(r.Context(), parsed)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load snapshot")
			return
		}
		if snapshot == nil {
			api.JSONError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		if snapshot.RefID != ref.ID {
			api.JSONError(w, http.StatusBadRequest, "snapshot does not belong to the selected ref")
			return
		}
		snapshotID = &parsed
	}

	release, err := s.queries.CreateRelease(r.Context(), repo.ID, ref.ID, snapshotID, input.Version, input.BuildMetadata, input.ArtifactIDs, input.Provenance, input.PublishedAt)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "release version already exists for this repository")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create release")
		return
	}

	api.JSON(w, http.StatusCreated, release)
}

// @Summary      List releases
// @Description  List releases for a repository visible to organization members
// @Tags         releases
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        repoSlug  path      string  true   "Repository slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.Release}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/releases [get]
func (s *Server) handleListReleases(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	releases, total, err := s.queries.ListReleasesByRepo(r.Context(), repo.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list releases")
		return
	}

	api.JSONList(w, releases, pagination.Page, pagination.PerPage, total)
}
