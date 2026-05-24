package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/store"
)

type uploadRequest struct {
	Provider      string `json:"provider"`
	Org           string `json:"org"`
	Repo          string `json:"repo"`
	Ref           string `json:"ref"`
	CommitSHA     string `json:"commit_sha"`
	SnapshotLabel string `json:"snapshot_label,omitempty"`
}

type sbomUploadRequest struct {
	uploadRequest
	Format   string         `json:"format"`
	Artifact uploadArtifact `json:"artifact"`
}

type sarifUploadRequest struct {
	uploadRequest
	Tool     string         `json:"tool"`
	Artifact uploadArtifact `json:"artifact"`
}

type findingsUploadRequest struct {
	uploadRequest
	Tool     string         `json:"tool"`
	Findings []findingInput `json:"findings"`
}

type uploadArtifact struct {
	Filename      string `json:"filename"`
	SHA256        string `json:"sha256,omitempty"`
	ContentBase64 string `json:"content_base64"`
}

type findingInput struct {
	RuleID    string         `json:"rule_id"`
	Severity  string         `json:"severity"`
	FilePath  string         `json:"file_path"`
	StartLine *int           `json:"start_line,omitempty"`
	EndLine   *int           `json:"end_line,omitempty"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type uploadResponse struct {
	UploadID   string `json:"upload_id"`
	SnapshotID string `json:"snapshot_id"`
	Status     string `json:"status"`
}

type uploadStatusResponse struct {
	UploadID   string `json:"upload_id"`
	SnapshotID string `json:"snapshot_id"`
	Status     string `json:"status"`
	RefID      string `json:"ref_id"`
	CommitSHA  string `json:"commit_sha"`
	CreatedAt  string `json:"created_at"`
}

// @Summary      Upload SBOM
// @Description  Creates a pending snapshot for an SBOM upload. Artifact parsing is deferred.
// @Tags         uploads
// @Accept       json
// @Produce      json
// @Param        body  body      server.sbomUploadRequest  true  "SBOM upload payload"
// @Success      202   {object}  api.Response{data=server.uploadResponse}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /upload/sbom [post]
func (s *Server) handleUploadSBOM(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var input sbomUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	normalizeUploadRequest(&input.uploadRequest)
	input.Format = strings.TrimSpace(input.Format)
	input.Artifact.ContentBase64 = strings.TrimSpace(input.Artifact.ContentBase64)

	if err := validateUploadRequest(input.uploadRequest); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.Format != "cyclonedx-json" && input.Format != "cyclonedx-xml" && input.Format != "spdx-json" && input.Format != "spdx-tv" {
		api.JSONError(w, http.StatusBadRequest, "format must be one of cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tv")
		return
	}
	if input.Artifact.ContentBase64 == "" {
		api.JSONError(w, http.StatusBadRequest, "artifact.content_base64 is required")
		return
	}
	if _, err := base64.StdEncoding.DecodeString(input.Artifact.ContentBase64); err != nil {
		api.JSONError(w, http.StatusBadRequest, "artifact.content_base64 must be valid base64")
		return
	}

	snapshot, err := s.createPendingUploadSnapshot(r, user.ID, input.uploadRequest, input.SnapshotLabel)
	if err != nil {
		s.writeUploadError(w, err)
		return
	}

	api.JSON(w, http.StatusAccepted, uploadResponse{
		UploadID:   snapshot.ID.String(),
		SnapshotID: snapshot.ID.String(),
		Status:     string(snapshot.Status),
	})
}

// @Summary      Upload SARIF
// @Description  Creates a pending snapshot for a SARIF upload. Artifact parsing is deferred.
// @Tags         uploads
// @Accept       json
// @Produce      json
// @Param        body  body      server.sarifUploadRequest  true  "SARIF upload payload"
// @Success      202   {object}  api.Response{data=server.uploadResponse}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /upload/sarif [post]
func (s *Server) handleUploadSARIF(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var input sarifUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	normalizeUploadRequest(&input.uploadRequest)
	input.Tool = strings.TrimSpace(input.Tool)
	input.Artifact.ContentBase64 = strings.TrimSpace(input.Artifact.ContentBase64)

	if err := validateUploadRequest(input.uploadRequest); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.Tool == "" {
		api.JSONError(w, http.StatusBadRequest, "tool is required")
		return
	}
	if input.Artifact.ContentBase64 == "" {
		api.JSONError(w, http.StatusBadRequest, "artifact.content_base64 is required")
		return
	}
	if _, err := base64.StdEncoding.DecodeString(input.Artifact.ContentBase64); err != nil {
		api.JSONError(w, http.StatusBadRequest, "artifact.content_base64 must be valid base64")
		return
	}

	label := input.Tool
	snapshot, err := s.createPendingUploadSnapshot(r, user.ID, input.uploadRequest, label)
	if err != nil {
		s.writeUploadError(w, err)
		return
	}

	api.JSON(w, http.StatusAccepted, uploadResponse{
		UploadID:   snapshot.ID.String(),
		SnapshotID: snapshot.ID.String(),
		Status:     string(snapshot.Status),
	})
}

// @Summary      Upload findings
// @Description  Creates a snapshot and stores the provided findings immediately.
// @Tags         uploads
// @Accept       json
// @Produce      json
// @Param        body  body      server.findingsUploadRequest  true  "Findings upload payload"
// @Success      202   {object}  api.Response{data=server.uploadResponse}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /upload/findings [post]
func (s *Server) handleUploadFindings(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var input findingsUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	normalizeUploadRequest(&input.uploadRequest)
	input.Tool = strings.TrimSpace(input.Tool)

	if err := validateUploadRequest(input.uploadRequest); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.Tool == "" {
		api.JSONError(w, http.StatusBadRequest, "tool is required")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := s.queries.WithTx(tx)
	_, repo, err := s.resolveUploadTarget(r, queries, user.ID, input.uploadRequest)
	if err != nil {
		s.writeUploadError(w, err)
		return
	}

	refType := refTypeFromName(input.Ref)
	refName := normalizeStoredRefName(input.Ref)
	ref, err := queries.UpsertRef(r.Context(), repo.ID, refName, refType, nil, nil, &input.CommitSHA)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}

	label := input.SnapshotLabel
	if label == "" {
		label = input.Tool
	}
	var snapshotLabel *string
	if label != "" {
		snapshotLabel = &label
	}

	snapshot, err := queries.CreateSnapshot(r.Context(), ref.ID, input.CommitSHA, snapshotLabel, store.SnapshotStatusPending, nil)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create upload")
		return
	}

	for _, finding := range input.Findings {
		severity, err := severityFromString(finding.Severity)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if strings.TrimSpace(finding.RuleID) == "" {
			api.JSONError(w, http.StatusBadRequest, "finding.rule_id is required")
			return
		}
		if strings.TrimSpace(finding.FilePath) == "" {
			api.JSONError(w, http.StatusBadRequest, "finding.file_path is required")
			return
		}
		if strings.TrimSpace(finding.Message) == "" {
			api.JSONError(w, http.StatusBadRequest, "finding.message is required")
			return
		}

		metadata, err := json.Marshal(finding.Metadata)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "finding.metadata must be valid JSON")
			return
		}

		startLine := int32PtrFromInt(finding.StartLine)
		endLine := int32PtrFromInt(finding.EndLine)
		locationHash := findingLocationHash(input.Tool, strings.TrimSpace(finding.RuleID), strings.TrimSpace(finding.FilePath), startLine, endLine)
		fingerprint := optionalMetadataString(finding.Metadata, "fingerprint")

		if _, err := queries.CreateFinding(
			r.Context(),
			snapshot.ID,
			input.Tool,
			strings.TrimSpace(finding.RuleID),
			severity,
			"open",
			strings.TrimSpace(finding.FilePath),
			startLine,
			endLine,
			locationHash,
			strings.TrimSpace(finding.Message),
			fingerprint,
			metadata,
		); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to create finding")
			return
		}
	}

	snapshot, err = queries.UpdateSnapshotStatus(r.Context(), snapshot.ID, store.SnapshotStatusComplete)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to finalize upload")
		return
	}

	if err := tx.Commit(); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to finalize upload")
		return
	}

	api.JSON(w, http.StatusAccepted, uploadResponse{
		UploadID:   snapshot.ID.String(),
		SnapshotID: snapshot.ID.String(),
		Status:     string(snapshot.Status),
	})
}

// @Summary      Get upload status
// @Description  Returns the current status for an upload snapshot.
// @Tags         uploads
// @Produce      json
// @Param        id  path      string  true  "Snapshot ID"
// @Success      200  {object}  api.Response{data=server.uploadStatusResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      500  {object}  api.Response
// @Security     BearerAuth
// @Router       /uploads/{id}/status [get]
func (s *Server) handleGetUploadStatus(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	snapshotID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid upload id")
		return
	}

	snapshot, err := s.queries.GetSnapshotByID(r.Context(), snapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load upload status")
		return
	}
	if snapshot == nil {
		api.JSONError(w, http.StatusNotFound, "upload not found")
		return
	}

	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load upload status")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "upload not found")
		return
	}

	repo, err := s.queries.GetRepositoryByID(r.Context(), ref.RepoID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load upload status")
		return
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, "upload not found")
		return
	}

	role, err := s.queries.GetOrgMemberRole(r.Context(), repo.OrgID, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load upload status")
		return
	}
	if role == "" {
		api.JSONError(w, http.StatusNotFound, "upload not found")
		return
	}

	api.JSON(w, http.StatusOK, uploadStatusResponse{
		UploadID:   snapshot.ID.String(),
		SnapshotID: snapshot.ID.String(),
		Status:     string(snapshot.Status),
		RefID:      snapshot.RefID.String(),
		CommitSHA:  snapshot.CommitSHA,
		CreatedAt:  snapshot.CreatedAt.UTC().Format(http.TimeFormat),
	})
}

func (s *Server) createPendingUploadSnapshot(r *http.Request, userID uuid.UUID, input uploadRequest, defaultLabel string) (*store.Snapshot, error) {
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := s.queries.WithTx(tx)
	_, repo, err := s.resolveUploadTarget(r, queries, userID, input)
	if err != nil {
		return nil, err
	}

	refType := refTypeFromName(input.Ref)
	refName := normalizeStoredRefName(input.Ref)
	ref, err := queries.UpsertRef(r.Context(), repo.ID, refName, refType, nil, nil, &input.CommitSHA)
	if err != nil {
		return nil, err
	}

	label := input.SnapshotLabel
	if label == "" {
		label = defaultLabel
	}
	var snapshotLabel *string
	if label != "" {
		snapshotLabel = &label
	}

	snapshot, err := queries.CreateSnapshot(r.Context(), ref.ID, input.CommitSHA, snapshotLabel, store.SnapshotStatusPending, nil)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return snapshot, nil
}

func (s *Server) resolveUploadTarget(r *http.Request, queries *store.Queries, userID uuid.UUID, input uploadRequest) (*store.Organization, *store.Repository, error) {
	org, err := queries.GetOrganizationByProviderAndSlug(r.Context(), input.Provider, input.Org)
	if err != nil {
		return nil, nil, err
	}
	if org == nil {
		return nil, nil, errNotFound("organization not found")
	}

	role, err := queries.GetOrgMemberRole(r.Context(), org.ID, userID)
	if err != nil {
		return nil, nil, err
	}
	if role == "" {
		return nil, nil, errNotFound("organization not found")
	}

	repo, err := queries.GetRepositoryBySlug(r.Context(), org.ID, input.Repo)
	if err != nil {
		return nil, nil, err
	}
	if repo == nil {
		return nil, nil, errNotFound("repository not found")
	}

	return org, repo, nil
}

func normalizeUploadRequest(input *uploadRequest) {
	input.Provider = strings.TrimSpace(input.Provider)
	input.Org = strings.TrimSpace(input.Org)
	input.Repo = strings.TrimSpace(input.Repo)
	input.Ref = strings.TrimSpace(input.Ref)
	input.CommitSHA = strings.TrimSpace(input.CommitSHA)
	input.SnapshotLabel = strings.TrimSpace(input.SnapshotLabel)
}

func validateUploadRequest(input uploadRequest) error {
	if input.Provider == "" {
		return fmt.Errorf("provider is required")
	}
	if input.Org == "" {
		return fmt.Errorf("org is required")
	}
	if input.Repo == "" {
		return fmt.Errorf("repo is required")
	}
	if input.Ref == "" {
		return fmt.Errorf("ref is required")
	}
	if input.CommitSHA == "" {
		return fmt.Errorf("commit_sha is required")
	}
	return nil
}

func refTypeFromName(name string) store.RefType {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "refs/pull/") || strings.HasPrefix(name, "refs/merge-requests/") {
		return store.RefTypePullRequest
	}
	if strings.HasPrefix(name, "refs/tags/") {
		return store.RefTypeTag
	}
	return store.RefTypeBranch
}

func normalizeStoredRefName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "refs/heads/") {
		return strings.TrimPrefix(name, "refs/heads/")
	}
	if strings.HasPrefix(name, "refs/tags/") {
		return strings.TrimPrefix(name, "refs/tags/")
	}
	return name
}

func severityFromString(value string) (store.SeverityLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return store.SeverityLevelCritical, nil
	case "high":
		return store.SeverityLevelHigh, nil
	case "medium":
		return store.SeverityLevelMedium, nil
	case "low":
		return store.SeverityLevelLow, nil
	case "info", "informational":
		return store.SeverityLevelInfo, nil
	default:
		return "", fmt.Errorf("finding.severity must be one of critical, high, medium, low, info")
	}
}

func findingLocationHash(tool, ruleID, filePath string, startLine, endLine *int32) string {
	start := ""
	if startLine != nil {
		start = fmt.Sprintf("%d", *startLine)
	}
	end := ""
	if endLine != nil {
		end = fmt.Sprintf("%d", *endLine)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{tool, ruleID, filePath, start, end}, ":")))
	return hex.EncodeToString(sum[:])
}

func int32PtrFromInt(value *int) *int32 {
	if value == nil {
		return nil
	}
	converted := int32(*value)
	return &converted
}

func optionalMetadataString(metadata map[string]any, key string) *string {
	if metadata == nil {
		return nil
	}
	value, ok := metadata[key]
	if !ok {
		return nil
	}
	text := strings.TrimSpace(fmt.Sprint(value))
	if text == "" || text == "<nil>" {
		return nil
	}
	return &text
}

type notFoundError struct {
	message string
}

func (e notFoundError) Error() string {
	return e.message
}

func errNotFound(message string) error {
	return notFoundError{message: message}
}

func (s *Server) writeUploadError(w http.ResponseWriter, err error) {
	if err == nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to process upload")
		return
	}

	var notFound notFoundError
	if ok := strings.Contains(err.Error(), "required"); ok {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.Contains(err.Error(), "invalid") {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if ok := errorAsNotFound(err, &notFound); ok {
		api.JSONError(w, http.StatusNotFound, notFound.message)
		return
	}

	api.JSONError(w, http.StatusInternalServerError, "failed to process upload")
}

func errorAsNotFound(err error, target *notFoundError) bool {
	value, ok := err.(notFoundError)
	if !ok {
		return false
	}
	*target = value
	return true
}
