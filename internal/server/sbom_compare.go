package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store"
)

type compareSBOMsRequest struct {
	BaseArtifactID string `json:"base_artifact_id"`
	HeadArtifactID string `json:"head_artifact_id"`
	BaseContent    string `json:"base_content"`
	BaseFormat     string `json:"base_format"`
	HeadContent    string `json:"head_content"`
	HeadFormat     string `json:"head_format"`
}

type compareSBOMInput struct {
	ArtifactID string
	Content    string
	Format     string
}

func (s *Server) handleCompareSBOMs(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	var input compareSBOMsRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	baseComponents, ok := s.loadComparableSBOMComponents(r, w, repo, "base", compareSBOMInput{
		ArtifactID: input.BaseArtifactID,
		Content:    input.BaseContent,
		Format:     input.BaseFormat,
	})
	if !ok {
		return
	}
	headComponents, ok := s.loadComparableSBOMComponents(r, w, repo, "head", compareSBOMInput{
		ArtifactID: input.HeadArtifactID,
		Content:    input.HeadContent,
		Format:     input.HeadFormat,
	})
	if !ok {
		return
	}

	api.JSON(w, http.StatusOK, sbom.Compare(baseComponents, headComponents))
}

func (s *Server) loadComparableSBOMComponents(r *http.Request, w http.ResponseWriter, repo *store.Repository, side string, input compareSBOMInput) ([]sbom.ParsedComponent, bool) {
	artifactID := strings.TrimSpace(input.ArtifactID)
	content := strings.TrimSpace(input.Content)
	format := strings.TrimSpace(input.Format)

	switch {
	case artifactID == "" && content == "":
		api.JSONError(w, http.StatusBadRequest, side+" input requires either artifact_id or content")
		return nil, false
	case artifactID != "" && content != "":
		api.JSONError(w, http.StatusBadRequest, side+" input must provide artifact_id or content, not both")
		return nil, false
	case artifactID != "":
		artifact, ok := s.loadAuthorizedSBOMArtifact(r, w, repo, artifactID)
		if !ok {
			return nil, false
		}
		artifactContent, ok := s.loadSnapshotArtifactContent(r, w, artifact)
		if !ok {
			return nil, false
		}
		return parseComparableSBOMContent(w, artifactContent, optionalStringValue(artifact.Format), "sbom artifact")
	default:
		if format == "" {
			api.JSONError(w, http.StatusBadRequest, side+" format is required when content is provided")
			return nil, false
		}
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, side+" content must be valid base64")
			return nil, false
		}
		return parseComparableSBOMContent(w, decoded, format, "inline sbom")
	}
}

func parseComparableSBOMContent(w http.ResponseWriter, content []byte, format string, source string) ([]sbom.ParsedComponent, bool) {
	var components []sbom.ParsedComponent
	var err error
	switch format {
	case "cyclonedx-json":
		components, err = sbom.ParseCycloneDXJSON(content)
	case "spdx-json":
		components, err = sbom.ParseSPDXJSON(content)
	default:
		api.JSONError(w, http.StatusBadRequest, "unsupported sbom format: "+format+"; only cyclonedx-json and spdx-json are supported")
		return nil, false
	}
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "failed to parse "+source+": "+err.Error())
		return nil, false
	}
	return components, true
}

func (s *Server) loadAuthorizedSBOMArtifact(r *http.Request, w http.ResponseWriter, repo *store.Repository, artifactID string) (*store.SnapshotArtifact, bool) {
	parsed, err := uuid.Parse(strings.TrimSpace(artifactID))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid artifact")
		return nil, false
	}

	artifact, err := s.queries.GetSnapshotArtifactByID(r.Context(), parsed)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load artifact")
		return nil, false
	}
	if artifact == nil {
		api.JSONError(w, http.StatusNotFound, "artifact not found")
		return nil, false
	}
	if artifact.Kind != "sbom" {
		api.JSONError(w, http.StatusBadRequest, "artifact is not an sbom")
		return nil, false
	}

	snapshot, err := s.queries.GetSnapshotByID(r.Context(), artifact.SnapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load artifact snapshot")
		return nil, false
	}
	if snapshot == nil {
		api.JSONError(w, http.StatusNotFound, "artifact snapshot not found")
		return nil, false
	}
	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load artifact reference")
		return nil, false
	}
	if ref == nil || ref.RepoID != repo.ID {
		api.JSONError(w, http.StatusForbidden, "artifact does not belong to this repository")
		return nil, false
	}

	return artifact, true
}

func (s *Server) loadSnapshotArtifactContent(r *http.Request, w http.ResponseWriter, artifact *store.SnapshotArtifact) ([]byte, bool) {
	if s.objStore == nil {
		api.JSONError(w, http.StatusInternalServerError, "artifact store is not configured")
		return nil, false
	}
	rc, err := s.objStore.Get(r.Context(), artifact.ObjectKey)
	if err != nil {
		api.JSONError(w, http.StatusNotFound, "artifact is no longer available")
		return nil, false
	}
	defer func() { _ = rc.Close() }()

	content, err := io.ReadAll(rc)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to read artifact")
		return nil, false
	}
	return content, true
}
