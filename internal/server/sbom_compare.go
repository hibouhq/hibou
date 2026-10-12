package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
	if !decodeSBOMCompareRequest(w, r, &input) {
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

// maxSBOMCompareBytes caps the request body of both compare endpoints, inline
// documents included (base64 inflates them by a third). Parsing holds several
// copies of each document, and the Tools variant is open to any logged-in
// user, so the cap stays small; larger SBOMs are compared as uploaded
// snapshot artifacts through the repository endpoint.
const maxSBOMCompareBytes = 8 << 20

func decodeSBOMCompareRequest(w http.ResponseWriter, r *http.Request, input *compareSBOMsRequest) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSBOMCompareBytes)).Decode(input)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		api.JSONError(w, http.StatusRequestEntityTooLarge, "request body exceeds the 8MB compare limit")
		return false
	}
	api.JSONError(w, http.StatusBadRequest, "invalid request body")
	return false
}

// @Summary      Compare two SBOM files
// @Description  The Tools SBOM comparator without a repository: both sides are inline documents (base64 CycloneDX or SPDX JSON) the caller sends, so nothing stored is read and no repository access is needed. Repository snapshot artifacts are compared through the repository's own endpoint.
// @Tags         tools
// @Accept       json
// @Produce      json
// @Param        request  body  server.compareSBOMsRequest  true  "Inline base and head documents"
// @Success      200  {object}  api.Response{data=sbom.SBOMDiff}
// @Failure      400  {object}  api.Response
// @Router       /tools/sbom/compare [post]
func (s *Server) handleCompareLocalSBOMs(w http.ResponseWriter, r *http.Request) {
	var input compareSBOMsRequest
	if !decodeSBOMCompareRequest(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.BaseArtifactID) != "" || strings.TrimSpace(input.HeadArtifactID) != "" {
		api.JSONError(w, http.StatusBadRequest, "artifacts belong to a repository; compare them through the repository's sbom/compare endpoint")
		return
	}
	baseComponents, ok := s.loadComparableSBOMComponents(r, w, nil, "base", compareSBOMInput{Content: input.BaseContent, Format: input.BaseFormat})
	if !ok {
		return
	}
	headComponents, ok := s.loadComparableSBOMComponents(r, w, nil, "head", compareSBOMInput{Content: input.HeadContent, Format: input.HeadFormat})
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
