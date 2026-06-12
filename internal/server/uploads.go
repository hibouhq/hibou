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

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/metrics"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/vex"
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

type detectedUpload struct {
	input        *autoUploadRequest
	content      []byte
	detectedType string
	format       string
	tool         string
	status       *string
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
			if uploadType, format, toolName, ok := detectJSONArtifactType(probe, trimmed); ok {
				return uploadType, format, toolName, nil
			}
		}
	}

	if trimmed[0] == '<' {
		prefix := trimmed
		if len(prefix) > 1024 {
			prefix = prefix[:1024]
		}
		if uploadType, format, toolName, ok := detectXMLArtifactType(prefix); ok {
			return uploadType, format, toolName, nil
		}
	}

	if uploadType, format, toolName, ok := detectTextArtifactType(trimmed); ok {
		return uploadType, format, toolName, nil
	}

	return "", "", "", errors.New("could not detect artifact type from content")
}

func detectJSONArtifactType(probe map[string]json.RawMessage, content []byte) (string, string, string, bool) {
	if raw, ok := probe["@context"]; ok {
		var ctx string
		if json.Unmarshal(raw, &ctx) == nil && strings.Contains(ctx, "openvex.dev") {
			return "vex", "openvex", "", true
		}
	}
	if raw, ok := probe["document"]; ok {
		var doc struct {
			Category string `json:"category"`
		}
		if json.Unmarshal(raw, &doc) == nil && doc.Category == "csaf_vex" {
			return "vex", "csaf", "", true
		}
	}
	if _, ok := probe["bomFormat"]; ok {
		return "sbom", "cyclonedx-json", "", true
	}
	if _, ok := probe["spdxVersion"]; ok {
		return "sbom", "spdx-json", "", true
	}
	if _, ok := probe["runs"]; ok {
		return "sarif", "", extractSARIFToolName(content), true
	}
	if raw, ok := probe["$schema"]; ok {
		var schema string
		if json.Unmarshal(raw, &schema) == nil && strings.Contains(strings.ToLower(schema), "sarif") {
			return "sarif", "", extractSARIFToolName(content), true
		}
	}
	return "", "", "", false
}

func detectXMLArtifactType(prefix []byte) (string, string, string, bool) {
	prefixLower := bytes.ToLower(prefix)
	if bytes.Contains(prefix, []byte("cyclonedx.org/schema/bom")) {
		return "sbom", "cyclonedx-xml", "", true
	}
	if bytes.Contains(prefix, []byte("spdx:Document")) || bytes.Contains(prefix, []byte("http://spdx.org/rdf")) {
		return "sbom", "spdx-xml", "", true
	}
	if bytes.Contains(prefixLower, []byte("<coverage")) && (bytes.Contains(prefixLower, []byte("line-rate")) || bytes.Contains(prefixLower, []byte("branch-rate"))) {
		return "coverage", "cobertura", "", true
	}
	if bytes.Contains(prefixLower, []byte("<report")) && bytes.Contains(prefixLower, []byte("jacoco")) {
		return "coverage", "jacoco", "", true
	}
	if bytes.Contains(prefixLower, []byte("<coverage")) && bytes.Contains(prefixLower, []byte("clover")) {
		return "coverage", "clover", "", true
	}
	return "", "", "", false
}

func detectTextArtifactType(content []byte) (string, string, string, bool) {
	if bytes.HasPrefix(content, []byte("SPDXVersion:")) {
		return "sbom", "spdx-tv", "", true
	}
	if bytes.HasPrefix(content, []byte("TN:")) || bytes.HasPrefix(content, []byte("SF:")) {
		return "coverage", "lcov", "", true
	}
	if bytes.HasPrefix(content, []byte("mode:")) {
		return "coverage", "gocover", "", true
	}
	return "", "", "", false
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

	input, content, err := s.parseAutoUploadRequest(w, r)
	if err != nil {
		if err.Error() != "" {
			api.JSONError(w, http.StatusBadRequest, err.Error())
		}
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

	_ = s.handleDetectedUploadType(w, r, user.ID, detectedUpload{
		input:        input,
		content:      content,
		detectedType: detectedType,
		format:       format,
		tool:         tool,
		status:       &status,
	})
}

func (s *Server) parseAutoUploadRequest(w http.ResponseWriter, r *http.Request) (*autoUploadRequest, []byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadSize)
	var input autoUploadRequest
	if !decodeUploadJSONBody(w, r, &input) {
		return nil, nil, errors.New("")
	}
	normalizeUploadRequest(&input.uploadRequest)
	input.Tool = strings.TrimSpace(input.Tool)
	if err := validateUploadRequest(input.uploadRequest); err != nil {
		return nil, nil, err
	}
	content, err := decodeAutoUploadArtifact(input.Artifact)
	if err != nil {
		return nil, nil, err
	}
	return &input, content, nil
}

func decodeAutoUploadArtifact(artifact *uploadArtifact) ([]byte, error) {
	if artifact == nil {
		return nil, errors.New("artifact is required")
	}
	artifact.ContentBase64 = strings.TrimSpace(artifact.ContentBase64)
	if artifact.ContentBase64 == "" {
		return nil, errors.New("artifact.content_base64 is required")
	}
	content, err := base64.StdEncoding.DecodeString(artifact.ContentBase64)
	if err != nil {
		return nil, errors.New("artifact.content_base64 must be valid base64")
	}
	return content, nil
}

func (s *Server) handleDetectedUploadType(w http.ResponseWriter, r *http.Request, userID uuid.UUID, upload detectedUpload) bool {
	switch upload.detectedType {
	case "sbom":
		return s.handleSBOMUpload(w, r, userID, upload.input, upload.format, upload.status)
	case "sarif":
		return s.handleSARIFUpload(w, r, userID, upload.input, upload.tool, upload.status)
	case "coverage":
		return s.handleCoverageUpload(w, r, userID, upload.input, upload.content, upload.format, upload.status)
	case "vex":
		if err := s.importUploadedVEX(r, userID, upload.input.uploadRequest, upload.input.Artifact, upload.format, upload.content); err != nil {
			s.writeUploadError(w, err)
			return false
		}
		*upload.status = "accepted"
		api.JSON(w, http.StatusAccepted, uploadResponse{Status: "accepted"})
		return true
	default:
		api.JSONError(w, http.StatusBadRequest, "could not detect artifact type from content")
		return false
	}
}

func (s *Server) handleSBOMUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, format string, status *string) bool {
	if format == "" {
		api.JSONError(w, http.StatusBadRequest, "could not determine SBOM format")
		return false
	}
	label := input.SnapshotLabel
	if label == "" {
		label = format
	}
	return s.writePendingUploadSnapshotResponse(w, r, userID, input.uploadRequest, label, status)
}

func (s *Server) handleSARIFUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, tool string, status *string) bool {
	if tool == "" {
		api.JSONError(w, http.StatusBadRequest, "tool could not be detected from SARIF content; provide 'tool' in the request")
		return false
	}
	return s.writePendingUploadSnapshotResponse(w, r, userID, input.uploadRequest, tool, status)
}

func (s *Server) handleCoverageUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, content []byte, format string, status *string) bool {
	label := input.SnapshotLabel
	if label == "" {
		label = format
	}
	snapshot, ok := s.createUploadSnapshot(w, r, userID, input.uploadRequest, label)
	if !ok {
		return false
	}
	go s.processCoverageUpload(snapshot.ID, content, format)
	*status = "accepted"
	api.JSON(w, http.StatusAccepted, uploadResponse{
		UploadID:   snapshot.ID.String(),
		SnapshotID: snapshot.ID.String(),
		Status:     string(snapshot.Status),
	})
	return true
}

func (s *Server) writePendingUploadSnapshotResponse(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input uploadRequest, label string, status *string) bool {
	snapshot, ok := s.createUploadSnapshot(w, r, userID, input, label)
	if !ok {
		return false
	}
	*status = "accepted"
	api.JSON(w, http.StatusAccepted, uploadResponse{
		UploadID:   snapshot.ID.String(),
		SnapshotID: snapshot.ID.String(),
		Status:     string(snapshot.Status),
	})
	return true
}

func (s *Server) createUploadSnapshot(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input uploadRequest, label string) (*store.Snapshot, bool) {
	snapshot, err := s.createPendingUploadSnapshot(r, userID, input, label)
	if err != nil {
		s.writeUploadError(w, err)
		return nil, false
	}
	return snapshot, true
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

func parseUploadedVEXStatements(format string, content []byte) ([]vex.Statement, error) {
	parsed, err := parseUploadedVEXDocument(format, content)
	if err != nil {
		return nil, errBadRequest(err.Error())
	}
	if len(parsed.Statements) == 0 {
		return nil, errBadRequest("VEX document did not contain any statements")
	}
	return parsed.Statements, nil
}

func resolveUploadedVEXSourceDocumentURL(artifact *uploadArtifact) string {
	if artifact == nil {
		return ""
	}
	return strings.TrimSpace(artifact.Filename)
}

func classifyUploadedVEXStatementError(index int, vulnerabilityID string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return errNotFound(fmt.Sprintf("advisory not found for vulnerability %q", strings.TrimSpace(vulnerabilityID)))
	}
	if err.Error() == "vulnerability_id is required" {
		return errBadRequest(fmt.Sprintf("invalid VEX statement %d: %s", index+1, err.Error()))
	}
	return err
}

type uploadedVEXImportContext struct {
	orgID             uuid.UUID
	repoID            uuid.UUID
	userID            uuid.UUID
	sourceDocumentURL string
}

func buildUploadedVEXStatementParams(ctx uploadedVEXImportContext, advisoryID uuid.UUID, statement vex.Statement) (dbgen.CreateVEXStatementParams, error) {
	params, err := buildCreateVEXParams(ctx.orgID, ctx.repoID, ctx.userID, advisoryID, createVEXStatementRequest{
		VulnerabilityID:   statement.VulnerabilityID,
		Status:            statement.Status,
		Justification:     statement.Justification,
		ImpactStatement:   statement.ImpactStatement,
		ActionStatement:   statement.ActionStatement,
		ComponentPURL:     statement.ComponentPURL,
		Source:            vex.SourceImported,
		SourceDocumentURL: ctx.sourceDocumentURL,
		Supplier:          statement.Supplier,
	})
	if err != nil {
		return dbgen.CreateVEXStatementParams{}, err
	}
	return params, nil
}

func (s *Server) importUploadedVEXStatement(r *http.Request, queries *store.Queries, ctx uploadedVEXImportContext, statement vex.Statement, index int) error {
	advisory, err := resolveVEXAdvisoryWithQueries(r.Context(), queries, statement.VulnerabilityID)
	if err != nil {
		return classifyUploadedVEXStatementError(index, statement.VulnerabilityID, err)
	}

	params, err := buildUploadedVEXStatementParams(ctx, advisory.ID, statement)
	if err != nil {
		return errBadRequest(fmt.Sprintf("invalid VEX statement %d: %s", index+1, err.Error()))
	}

	_, err = queries.CreateVEXStatement(r.Context(), params)
	return err
}

func (s *Server) importUploadedVEXStatements(r *http.Request, queries *store.Queries, ctx uploadedVEXImportContext, statements []vex.Statement) error {
	for index, statement := range statements {
		if err := s.importUploadedVEXStatement(r, queries, ctx, statement, index); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) importUploadedVEX(r *http.Request, userID uuid.UUID, input uploadRequest, artifact *uploadArtifact, format string, content []byte) error {
	statements, err := parseUploadedVEXStatements(format, content)
	if err != nil {
		return err
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

	importCtx := uploadedVEXImportContext{
		orgID:             org.ID,
		repoID:            repo.ID,
		userID:            userID,
		sourceDocumentURL: resolveUploadedVEXSourceDocumentURL(artifact),
	}
	if err := s.importUploadedVEXStatements(r, queries, importCtx, statements); err != nil {
		return err
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
