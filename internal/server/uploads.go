package server

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/metrics"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/vex"
)

type uploadRequest struct {
	Provider      string `json:"provider"`
	Org           string `json:"org"`
	Repo          string `json:"repo"`
	Ref           string `json:"ref"`
	CommitSHA     string `json:"commit_sha"`
	SnapshotLabel string `json:"snapshot_label,omitempty"`
}

type autoUploadRequest struct {
	uploadRequest
	Tool     string          `json:"tool,omitempty"`
	Artifact *uploadArtifact `json:"artifact,omitempty"`
	Complete *bool           `json:"complete,omitempty"`
	Expect   *int            `json:"expect,omitempty"`
}

type uploadArtifact struct {
	Filename      string `json:"filename"`
	SHA256        string `json:"sha256,omitempty"`
	ContentBase64 string `json:"content_base64"`
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

// detectArtifactType inspects the decoded content to determine the upload type and format.
// Returns (uploadType, format, toolName, error).
func detectArtifactType(content []byte) (string, string, string, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return "", "", "", errors.New("empty artifact content")
	}

	if trimmed[0] == '{' {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &probe); err == nil {
			if raw, ok := probe["@context"]; ok {
				var ctx string
				if json.Unmarshal(raw, &ctx) == nil && strings.Contains(ctx, "openvex.dev") {
					return "vex", "openvex", "", nil
				}
			}
			if raw, ok := probe["document"]; ok {
				var doc struct {
					Category string `json:"category"`
				}
				if json.Unmarshal(raw, &doc) == nil && doc.Category == "csaf_vex" {
					return "vex", "csaf", "", nil
				}
			}
			if _, ok := probe["bomFormat"]; ok {
				return "sbom", "cyclonedx-json", "", nil
			}
			if _, ok := probe["spdxVersion"]; ok {
				return "sbom", "spdx-json", "", nil
			}
			if _, ok := probe["runs"]; ok {
				return "sarif", "", extractSARIFToolName(trimmed), nil
			}
			if raw, ok := probe["$schema"]; ok {
				var schema string
				if json.Unmarshal(raw, &schema) == nil && strings.Contains(strings.ToLower(schema), "sarif") {
					return "sarif", "", extractSARIFToolName(trimmed), nil
				}
			}
		}
	}

	if trimmed[0] == '<' {
		prefix := trimmed
		if len(prefix) > 1024 {
			prefix = prefix[:1024]
		}
		prefixLower := bytes.ToLower(prefix)
		if bytes.Contains(prefix, []byte("cyclonedx.org/schema/bom")) {
			return "sbom", "cyclonedx-xml", "", nil
		}
		if bytes.Contains(prefix, []byte("spdx:Document")) || bytes.Contains(prefix, []byte("http://spdx.org/rdf")) {
			return "sbom", "spdx-xml", "", nil
		}
		if bytes.Contains(prefixLower, []byte("<coverage")) && (bytes.Contains(prefixLower, []byte("line-rate")) || bytes.Contains(prefixLower, []byte("branch-rate"))) {
			return "coverage", "cobertura", "", nil
		}
		if bytes.Contains(prefixLower, []byte("<report")) && bytes.Contains(prefixLower, []byte("jacoco")) {
			return "coverage", "jacoco", "", nil
		}
		if bytes.Contains(prefixLower, []byte("<coverage")) && bytes.Contains(prefixLower, []byte("clover")) {
			return "coverage", "clover", "", nil
		}
	}

	if bytes.HasPrefix(trimmed, []byte("SPDXVersion:")) {
		return "sbom", "spdx-tv", "", nil
	}
	if bytes.HasPrefix(trimmed, []byte("TN:")) || bytes.HasPrefix(trimmed, []byte("SF:")) {
		return "coverage", "lcov", "", nil
	}
	if bytes.HasPrefix(trimmed, []byte("mode:")) {
		return "coverage", "gocover", "", nil
	}

	return "", "", "", errors.New("could not detect artifact type from content")
}

func extractSARIFToolName(content []byte) string {
	var sarif struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if json.Unmarshal(content, &sarif) == nil && len(sarif.Runs) > 0 {
		return sarif.Runs[0].Tool.Driver.Name
	}
	return ""
}

// @Summary      Upload artifact (auto-detect)
// @Description  Creates a pending snapshot. Artifact type (SBOM, SARIF, coverage report, or VEX document) is auto-detected from content.
// @Tags         uploads
// @Accept       json
// @Produce      json
// @Param        payload  body      server.autoUploadRequest  true  "Upload payload"
// @Success      202   {object}  api.Response{data=server.uploadResponse}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /upload [post]
func (s *Server) handleUploadAuto(w http.ResponseWriter, r *http.Request) {
	uploadType := "auto"
	status := "rejected"
	defer func() {
		metrics.UploadsTotal.WithLabelValues(uploadType, status).Inc()
	}()

	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadSize)
	var input autoUploadRequest
	if !decodeUploadJSONBody(w, r, &input) {
		return
	}

	normalizeUploadRequest(&input.uploadRequest)
	input.Tool = strings.TrimSpace(input.Tool)

	if err := validateUploadRequest(input.uploadRequest); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if input.Artifact == nil {
		api.JSONError(w, http.StatusBadRequest, "artifact is required")
		return
	}
	input.Artifact.ContentBase64 = strings.TrimSpace(input.Artifact.ContentBase64)
	if input.Artifact.ContentBase64 == "" {
		api.JSONError(w, http.StatusBadRequest, "artifact.content_base64 is required")
		return
	}

	content, err := base64.StdEncoding.DecodeString(input.Artifact.ContentBase64)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "artifact.content_base64 must be valid base64")
		return
	}

	detectedType, format, detectedTool, err := detectArtifactType(content)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	uploadType = detectedType

	tool := input.Tool
	if tool == "" {
		tool = detectedTool
	}

	switch detectedType {
	case "sbom":
		if format == "" {
			api.JSONError(w, http.StatusBadRequest, "could not determine SBOM format")
			return
		}
		label := input.SnapshotLabel
		if label == "" {
			label = format
		}
		snapshot, err := s.createPendingUploadSnapshot(r, user.ID, input.uploadRequest, label)
		if err != nil {
			s.writeUploadError(w, err)
			return
		}
		status = "accepted"
		api.JSON(w, http.StatusAccepted, uploadResponse{
			UploadID:   snapshot.ID.String(),
			SnapshotID: snapshot.ID.String(),
			Status:     string(snapshot.Status),
		})
	case "sarif":
		if tool == "" {
			api.JSONError(w, http.StatusBadRequest, "tool could not be detected from SARIF content; provide 'tool' in the request")
			return
		}
		label := tool
		snapshot, err := s.createPendingUploadSnapshot(r, user.ID, input.uploadRequest, label)
		if err != nil {
			s.writeUploadError(w, err)
			return
		}
		status = "accepted"
		api.JSON(w, http.StatusAccepted, uploadResponse{
			UploadID:   snapshot.ID.String(),
			SnapshotID: snapshot.ID.String(),
			Status:     string(snapshot.Status),
		})
	case "coverage":
		label := input.SnapshotLabel
		if label == "" {
			label = format
		}
		snapshot, err := s.createPendingUploadSnapshot(r, user.ID, input.uploadRequest, label)
		if err != nil {
			s.writeUploadError(w, err)
			return
		}
		// TODO: replace fire-and-forget goroutine with a bounded worker pool or
		// the server's background task system for proper shutdown coordination.
		go s.processCoverageUpload(snapshot.ID, content, format) //nolint:gosec // G118: intentional background processing after request completes
		status = "accepted"
		api.JSON(w, http.StatusAccepted, uploadResponse{
			UploadID:   snapshot.ID.String(),
			SnapshotID: snapshot.ID.String(),
			Status:     string(snapshot.Status),
		})
	case "vex":
		if err := s.importUploadedVEX(r, user.ID, input.uploadRequest, input.Artifact, format, content); err != nil {
			s.writeUploadError(w, err)
			return
		}
		status = "accepted"
		api.JSON(w, http.StatusAccepted, uploadResponse{Status: "accepted"})
	default:
		api.JSONError(w, http.StatusBadRequest, "could not detect artifact type from content")
	}
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
	_, repo, err := s.resolveUploadScope(r, queries, userID, input)
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

func (s *Server) resolveUploadScope(r *http.Request, queries *store.Queries, userID uuid.UUID, input uploadRequest) (*store.Organization, *store.Repository, error) {
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

func (s *Server) importUploadedVEX(r *http.Request, userID uuid.UUID, input uploadRequest, artifact *uploadArtifact, format string, content []byte) error {
	parsed, err := parseUploadedVEXDocument(format, content)
	if err != nil {
		return errBadRequest(err.Error())
	}
	if len(parsed.Statements) == 0 {
		return errBadRequest("VEX document did not contain any statements")
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := s.queries.WithTx(tx)
	org, repo, err := s.resolveUploadScope(r, queries, userID, input)
	if err != nil {
		return err
	}

	sourceDocumentURL := ""
	if artifact != nil {
		sourceDocumentURL = strings.TrimSpace(artifact.Filename)
	}

	for index, statement := range parsed.Statements {
		advisory, advisoryErr := resolveVEXAdvisoryWithQueries(r.Context(), queries, statement.VulnerabilityID)
		if advisoryErr != nil {
			if errors.Is(advisoryErr, sql.ErrNoRows) {
				return errNotFound(fmt.Sprintf("advisory not found for vulnerability %q", strings.TrimSpace(statement.VulnerabilityID)))
			}
			if advisoryErr.Error() == "vulnerability_id is required" {
				return errBadRequest(fmt.Sprintf("invalid VEX statement %d: %s", index+1, advisoryErr.Error()))
			}
			return advisoryErr
		}

		params, paramsErr := buildCreateVEXParams(org.ID, repo.ID, userID, advisory.ID, createVEXStatementRequest{
			VulnerabilityID:   statement.VulnerabilityID,
			Status:            statement.Status,
			Justification:     statement.Justification,
			ImpactStatement:   statement.ImpactStatement,
			ActionStatement:   statement.ActionStatement,
			ComponentPURL:     statement.ComponentPURL,
			Source:            vex.SourceImported,
			SourceDocumentURL: sourceDocumentURL,
			Supplier:          statement.Supplier,
		})
		if paramsErr != nil {
			return errBadRequest(fmt.Sprintf("invalid VEX statement %d: %s", index+1, paramsErr.Error()))
		}

		if _, err := queries.CreateVEXStatement(r.Context(), params); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func parseUploadedVEXDocument(format string, content []byte) (*vex.ParseResult, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case vex.FormatOpenVEX:
		return vex.ParseOpenVEX(content)
	case vex.FormatCSAF:
		return vex.ParseCSAF(content)
	default:
		return nil, fmt.Errorf("unsupported VEX format %q", format)
	}
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
		return errors.New("provider is required")
	}
	if input.Org == "" {
		return errors.New("org is required")
	}
	if input.Repo == "" {
		return errors.New("repo is required")
	}
	if input.Ref == "" {
		return errors.New("ref is required")
	}
	if input.CommitSHA == "" {
		return errors.New("commit_sha is required")
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

type badRequestError struct {
	message string
}

func (e badRequestError) Error() string {
	return e.message
}

func errBadRequest(message string) error {
	return badRequestError{message: message}
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

	var badRequest badRequestError
	var notFound notFoundError
	if ok := errorAsBadRequest(err, &badRequest); ok {
		api.JSONError(w, http.StatusBadRequest, badRequest.message)
		return
	}
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

func decodeUploadJSONBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			api.JSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func errorAsBadRequest(err error, target *badRequestError) bool {
	return errors.As(err, target)
}

func errorAsNotFound(err error, target *notFoundError) bool {
	return errors.As(err, target)
}
