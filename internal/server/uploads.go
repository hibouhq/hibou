package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/metrics"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/vex"
)

type uploadRequest struct {
	Provider       string `json:"provider"`
	Org            string `json:"org"`
	Repo           string `json:"repo"`
	Ref            string `json:"ref"`
	CommitSHA      string `json:"commit_sha"`
	RunID          string `json:"run_id,omitempty"`
	RunAttempt     string `json:"run_attempt,omitempty"`
	RunNumber      string `json:"run_number,omitempty"`
	BuildURL       string `json:"build_url,omitempty"`
	PRNumber       string `json:"pr_number,omitempty"`
	PRTargetBranch string `json:"pr_target_branch,omitempty"`
	PRSourceBranch string `json:"pr_source_branch,omitempty"`
	PRTitle        string `json:"pr_title,omitempty"`
	Tag            string `json:"tag,omitempty"`
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

type rawArtifactPayload struct {
	kind     string
	format   string
	tool     string
	filename string
	content  []byte
}

// uploadArtifactFilename returns the original filename the client sent, if any.
func uploadArtifactFilename(input *autoUploadRequest) string {
	if input != nil && input.Artifact != nil {
		return strings.TrimSpace(input.Artifact.Filename)
	}
	return ""
}

const (
	uploadNotFoundMessage    = "upload not found"
	failedToLoadUploadStatus = "failed to load upload status"
	refsHeadsPrefix          = "refs/heads/"
	refsTagsPrefix           = "refs/tags/"
	defaultMaxUploadSize     = int64(104857600)
)

var (
	prNumberPattern = regexp.MustCompile(`^refs/(pull|merge-requests)/(\d+)(?:/.*)?$`)
	// prCanonicalPattern matches a head/merge PR ref and captures the canonical
	// form (refs/pull/N or refs/merge-requests/N) without the trailing segment.
	prCanonicalPattern = regexp.MustCompile(`^(refs/(?:pull|merge-requests)/\d+)/(?:head|merge)$`)
)

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
	if bytes.Contains(prefixLower, []byte("<testsuites")) || bytes.Contains(prefixLower, []byte("<testsuite")) {
		return "tests", "junit", "", true
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

	if input.Artifact == nil {
		snapshot, ok := s.completeUploadSnapshot(w, r, user.ID, input)
		if !ok {
			return
		}
		status = "accepted"
		api.JSON(w, http.StatusAccepted, uploadResponse{
			UploadID:   snapshot.ID.String(),
			SnapshotID: snapshot.ID.String(),
			Status:     string(snapshot.Status),
		})
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
	// max.upload.size is the authoritative raw-artifact cap. Object-store writes
	// only persist the already-bounded decoded bytes so backend selection does not
	// introduce a second divergent limit.
	maxUploadSize := s.cfg.MaxUploadSize
	if maxUploadSize <= 0 {
		maxUploadSize = defaultMaxUploadSize
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	var input autoUploadRequest
	if !decodeUploadJSONBody(w, r, &input) {
		return nil, nil, errors.New("")
	}
	normalizeUploadRequest(&input.uploadRequest)
	input.Tool = strings.TrimSpace(input.Tool)
	if err := validateUploadRequest(input.uploadRequest); err != nil {
		return nil, nil, err
	}
	if input.Artifact == nil {
		if input.Complete != nil && *input.Complete {
			return &input, nil, nil
		}
		return nil, nil, errors.New("artifact is required")
	}
	// Decode early so type detection can inspect raw bytes before routing.
	// Raw object persistence still happens only after the snapshot row exists.
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
		return s.handleSBOMUpload(w, r, userID, upload.input, upload.content, upload.format, upload.status)
	case "sarif":
		return s.handleSARIFUpload(w, r, userID, upload.input, upload.content, upload.tool, upload.status)
	case "coverage":
		return s.handleCoverageUpload(w, r, userID, upload.input, upload.content, upload.format, upload.status)
	case "tests":
		return s.handleTestsUpload(w, r, userID, upload.input, upload.content, upload.format, upload.status)
	case "vex":
		return s.handleVEXUpload(w, r, userID, upload.input, upload.content, upload.format, upload.status)
	default:
		api.JSONError(w, http.StatusBadRequest, "could not detect artifact type from content")
		return false
	}
}

func (s *Server) handleSBOMUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, content []byte, format string, status *string) bool {
	if format == "" {
		api.JSONError(w, http.StatusBadRequest, "could not determine SBOM format")
		return false
	}
	return s.writePendingUploadSnapshotResponse(w, r, userID, input, rawArtifactPayload{
		kind:     "sbom",
		format:   format,
		tool:     input.Tool,
		filename: uploadArtifactFilename(input),
		content:  content,
	}, status)
}

func (s *Server) handleSARIFUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, content []byte, tool string, status *string) bool {
	if tool == "" {
		api.JSONError(w, http.StatusBadRequest, "tool could not be detected from SARIF content; provide 'tool' in the request")
		return false
	}
	return s.writePendingUploadSnapshotResponse(w, r, userID, input, rawArtifactPayload{
		kind:     "sarif",
		tool:     tool,
		filename: uploadArtifactFilename(input),
		content:  content,
	}, status)
}

func (s *Server) handleCoverageUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, content []byte, format string, status *string) bool {
	snapshot, ok := s.createUploadSnapshot(w, r, userID, input, true, &rawArtifactPayload{
		kind:     "coverage",
		format:   format,
		tool:     input.Tool,
		filename: uploadArtifactFilename(input),
		content:  content,
	})
	if !ok {
		return false
	}
	go s.processCoverageUpload(context.WithoutCancel(r.Context()), snapshot.ID, content, format)
	snapshot, ok = s.completeUploadSnapshotIfNeeded(w, r, input, snapshot)
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

func (s *Server) handleTestsUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, content []byte, format string, status *string) bool {
	snapshot, ok := s.createUploadSnapshot(w, r, userID, input, true, &rawArtifactPayload{
		kind:     "tests",
		format:   format,
		tool:     input.Tool,
		filename: uploadArtifactFilename(input),
		content:  content,
	})
	if !ok {
		return false
	}
	testSource := ""
	if input.Artifact != nil {
		testSource = strings.TrimSpace(input.Artifact.Filename)
	}
	go s.processTestUpload(context.WithoutCancel(r.Context()), snapshot.ID, content, format, testSource)
	snapshot, ok = s.completeUploadSnapshotIfNeeded(w, r, input, snapshot)
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

func (s *Server) handleVEXUpload(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, content []byte, format string, status *string) bool {
	snapshot, ok := s.createUploadSnapshot(w, r, userID, input, true, &rawArtifactPayload{
		kind:     "vex",
		format:   format,
		tool:     input.Tool,
		filename: uploadArtifactFilename(input),
		content:  content,
	})
	if !ok {
		return false
	}
	if err := s.importUploadedVEX(r, userID, input.uploadRequest, input.Artifact, format, content); err != nil {
		s.writeUploadError(w, err)
		return false
	}
	snapshot, ok = s.completeUploadSnapshotIfNeeded(w, r, input, snapshot)
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

func (s *Server) writePendingUploadSnapshotResponse(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, artifact rawArtifactPayload, status *string) bool {
	snapshot, ok := s.createUploadSnapshot(w, r, userID, input, true, &artifact)
	if !ok {
		return false
	}
	snapshot, ok = s.completeUploadSnapshotIfNeeded(w, r, input, snapshot)
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

func (s *Server) createUploadSnapshot(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest, incrementReceived bool, artifact *rawArtifactPayload) (*store.Snapshot, bool) {
	snapshot, err := s.createPendingUploadSnapshot(r, userID, input.uploadRequest, input.Expect)
	if err != nil {
		s.writeUploadError(w, err)
		return nil, false
	}
	if incrementReceived {
		snapshot, err = s.advanceUploadSnapshot(r.Context(), snapshot.ID, artifact)
		if err != nil {
			s.writeUploadError(w, err)
			return nil, false
		}
	}
	return snapshot, true
}

func (s *Server) completeUploadSnapshot(w http.ResponseWriter, r *http.Request, userID uuid.UUID, input *autoUploadRequest) (*store.Snapshot, bool) {
	snapshot, err := s.loadUploadSnapshotForCompletion(r, userID, input.uploadRequest)
	if err != nil {
		s.writeUploadError(w, err)
		return nil, false
	}
	return s.completeUploadSnapshotIfNeeded(w, r, input, snapshot)
}

func (s *Server) loadUploadSnapshotForCompletion(r *http.Request, userID uuid.UUID, input uploadRequest) (*store.Snapshot, error) {
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

	refName := normalizeStoredRefName(input.Ref)
	ref, err := queries.UpsertRef(r.Context(), repo.ID, refName, refTypeFromName(input.Ref), buildUploadRefOptions(input))
	if err != nil {
		return nil, err
	}

	runID := optionalTrimmedString(input.RunID)
	var snapshot *store.Snapshot
	if strings.TrimSpace(input.RunAttempt) == "" {
		snapshot, err = queries.GetLatestSnapshotForBuild(r.Context(), ref.ID, input.CommitSHA, runID)
	} else {
		snapshot, err = queries.GetSnapshotByBuildIdentity(r.Context(), ref.ID, input.CommitSHA, runID, optionalTrimmedString(input.RunAttempt))
	}
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, errNotFound("no pending snapshot for ref/commit")
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return snapshot, nil
}

func (s *Server) advanceUploadSnapshot(ctx context.Context, snapshotID uuid.UUID, artifact *rawArtifactPayload) (*store.Snapshot, error) {
	var artifactParams *store.CreateSnapshotArtifactParams
	if artifact != nil {
		if s.objStore == nil {
			// Defensive only: server startup now fails if the configured artifact store cannot initialize.
			return nil, errors.New("artifact store unavailable")
		}
		params := buildSnapshotArtifactParams(snapshotID, artifact.kind, artifact.format, artifact.tool, artifact.filename, artifact.content)
		contentType := ""
		if params.ContentType != nil {
			contentType = *params.ContentType
		}
		if err := s.objStore.Put(ctx, params.ObjectKey, bytes.NewReader(artifact.content), contentType); err != nil {
			return nil, err
		}
		artifactParams = &params
	}
	if err := s.finalizeUploadSnapshotTx(ctx, snapshotID, artifactParams); err != nil {
		return nil, err
	}
	return s.loadSnapshotByID(ctx, snapshotID)
}

func buildSnapshotArtifactParams(snapshotID uuid.UUID, kind, format, tool, filename string, content []byte) store.CreateSnapshotArtifactParams {
	sum := sha256.Sum256(content)
	sha256Hex := hex.EncodeToString(sum[:])
	contentType := rawArtifactContentType(kind, format)
	return store.CreateSnapshotArtifactParams{
		SnapshotID:  snapshotID,
		Kind:        kind,
		Format:      optionalTrimmedString(format),
		ToolName:    optionalTrimmedString(tool),
		ObjectKey:   snapshotArtifactObjectKey(snapshotID, sha256Hex),
		SHA256:      &sha256Hex,
		SizeBytes:   int64(len(content)),
		ContentType: optionalTrimmedString(contentType),
		Filename:    strings.TrimSpace(filename),
	}
}

func (s *Server) finalizeUploadSnapshotTx(ctx context.Context, snapshotID uuid.UUID, artifactParams *store.CreateSnapshotArtifactParams) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := s.queries.WithTx(tx)
	if artifactParams != nil {
		if err := queries.LockSnapshotForUpdate(ctx, snapshotID); err != nil {
			return err
		}
		created, err := queries.CreateSnapshotArtifact(ctx, *artifactParams)
		if err != nil {
			return err
		}
		if created != nil {
			if err := queries.AddSnapshotArtifactBytes(ctx, snapshotID, artifactParams.SizeBytes); err != nil {
				return err
			}
		}
	}
	if _, err := queries.IncrementSnapshotReceivedUploads(ctx, snapshotID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Server) loadSnapshotByID(ctx context.Context, snapshotID uuid.UUID) (*store.Snapshot, error) {
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, errNotFound(uploadNotFoundMessage)
	}
	return snapshot, nil
}

func snapshotArtifactObjectKey(snapshotID uuid.UUID, sha256Hex string) string {
	return fmt.Sprintf("snapshots/%s/%s", snapshotID.String(), strings.TrimSpace(sha256Hex))
}

func rawArtifactContentType(kind, format string) string {
	switch strings.TrimSpace(kind) {
	case "sarif":
		return "application/sarif+json"
	case "sbom", "vex":
		if strings.HasSuffix(format, "-xml") {
			return "application/xml"
		}
		if format == "spdx-tv" {
			return "text/plain"
		}
		return "application/json"
	case "coverage":
		switch strings.TrimSpace(format) {
		case "lcov", "gocover":
			return "text/plain"
		default:
			return "application/xml"
		}
	case "tests":
		return "application/xml"
	default:
		return "application/octet-stream"
	}
}

func (s *Server) completeUploadSnapshotIfNeeded(w http.ResponseWriter, r *http.Request, input *autoUploadRequest, snapshot *store.Snapshot) (*store.Snapshot, bool) {
	explicitComplete := input.Complete != nil && *input.Complete
	shouldComplete := explicitComplete
	if !shouldComplete {
		expectedUploads := snapshot.ExpectedUploads
		if input.Expect != nil && *input.Expect > 0 {
			value := *input.Expect
			expectedUploads = &value
		}
		if expectedUploads != nil && *expectedUploads > 0 && snapshot.ReceivedUploads >= *expectedUploads {
			shouldComplete = true
		}
	}
	if !shouldComplete {
		return snapshot, true
	}

	completedSnapshot, err := s.queries.CompleteSnapshot(r.Context(), snapshot.ID)
	if err != nil {
		if errors.Is(err, store.ErrSnapshotNotCompletable) {
			if explicitComplete {
				s.writeUploadError(w, errConflict("snapshot already finalized or timed out"))
				return nil, false
			}
			s.log.Warn().Str("snapshot_id", snapshot.ID.String()).Msg("skipping snapshot auto-completion for finalized snapshot")
			currentSnapshot, loadErr := s.loadSnapshotByID(r.Context(), snapshot.ID)
			if loadErr != nil {
				s.writeUploadError(w, loadErr)
				return nil, false
			}
			return currentSnapshot, true
		}
		s.writeUploadError(w, err)
		return nil, false
	}
	if completedSnapshot == nil {
		s.writeUploadError(w, errNotFound(uploadNotFoundMessage))
		return nil, false
	}
	s.triggerRetentionPass()
	return completedSnapshot, true
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
		api.JSONError(w, http.StatusInternalServerError, failedToLoadUploadStatus)
		return
	}
	if snapshot == nil {
		api.JSONError(w, http.StatusNotFound, uploadNotFoundMessage)
		return
	}

	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, failedToLoadUploadStatus)
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, uploadNotFoundMessage)
		return
	}

	repo, err := s.queries.GetRepositoryByID(r.Context(), ref.RepoID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, failedToLoadUploadStatus)
		return
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, uploadNotFoundMessage)
		return
	}

	role, err := s.queries.GetOrgMemberRole(r.Context(), repo.OrgID, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, failedToLoadUploadStatus)
		return
	}
	if role == "" {
		api.JSONError(w, http.StatusNotFound, uploadNotFoundMessage)
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

func (s *Server) createPendingUploadSnapshot(r *http.Request, userID uuid.UUID, input uploadRequest, expect *int) (*store.Snapshot, error) {
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
	ref, err := queries.UpsertRef(r.Context(), repo.ID, refName, refType, buildUploadRefOptions(input))
	if err != nil {
		return nil, err
	}

	meta := store.SnapshotBuildMeta{
		BuildURL:        optionalTrimmedString(input.BuildURL),
		RunID:           optionalTrimmedString(input.RunID),
		RunAttempt:      optionalTrimmedString(input.RunAttempt),
		RunNumber:       optionalTrimmedString(input.RunNumber),
		PRNumber:        optionalTrimmedString(input.PRNumber),
		PRTargetBranch:  optionalTrimmedString(input.PRTargetBranch),
		Tag:             resolveUploadTag(input.Ref, input.Tag),
		ExpectedUploads: positiveInt32Ptr(expect),
	}
	// Auto-attempt (universal fallback): when no explicit run_attempt was provided, a fresh
	// upload arriving after the build's latest snapshot is no longer pending indicates a new
	// attempt (e.g. a pipeline retry). Synthesize a distinct attempt so the retry gets its own
	// snapshot instead of merging into the old one. Forges that expose a real attempt
	// (GitHub/Forgejo GITHUB_RUN_ATTEMPT, or an explicit HIBOU_RUN_ATTEMPT) send it as an
	// authoritative override and skip this branch, which keeps overlapping re-runs that reuse
	// the same run_id distinct. GitLab, lacking a native attempt variable, relies on this path.
	if meta.RunAttempt == nil {
		latest, err := queries.GetLatestSnapshotForBuild(r.Context(), ref.ID, input.CommitSHA, optionalTrimmedString(input.RunID))
		if err != nil {
			return nil, err
		}
		if latest != nil {
			if latest.Status == store.SnapshotStatusPending {
				meta.RunAttempt = latest.RunAttempt
			} else {
				count, err := queries.CountSnapshotsForBuild(r.Context(), ref.ID, input.CommitSHA, optionalTrimmedString(input.RunID))
				if err != nil {
					return nil, err
				}
				attempt := strconv.FormatInt(count, 10)
				meta.RunAttempt = &attempt
			}
		}
	}

	snapshot, err := queries.UpsertSnapshotForBuild(r.Context(), ref.ID, input.CommitSHA, store.SnapshotStatusPending, meta)
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

func resolveUploadedVEXSourceDocumentURL(artifact *uploadArtifact, content []byte) string {
	if artifact != nil {
		if filename := strings.TrimSpace(artifact.Filename); filename != "" {
			return filename
		}
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
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

type uploadedVEXStatementScope struct {
	advisoryID    uuid.UUID
	componentPURL string
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

func (s *Server) importUploadedVEXStatement(r *http.Request, tx *sql.Tx, queries *store.Queries, ctx uploadedVEXImportContext, statement vex.Statement, index int) (uploadedVEXStatementScope, error) {
	advisory, err := resolveVEXAdvisoryWithQueries(r.Context(), queries, statement.VulnerabilityID)
	if err != nil {
		return uploadedVEXStatementScope{}, classifyUploadedVEXStatementError(index, statement.VulnerabilityID, err)
	}

	params, err := buildUploadedVEXStatementParams(ctx, advisory.ID, statement)
	if err != nil {
		return uploadedVEXStatementScope{}, errBadRequest(fmt.Sprintf("invalid VEX statement %d: %s", index+1, err.Error()))
	}

	if err := upsertImportedVEXStatement(r.Context(), tx, params); err != nil {
		return uploadedVEXStatementScope{}, err
	}

	return uploadedVEXStatementScope{
		advisoryID:    advisory.ID,
		componentPURL: vexScopeComponentPURL(params.ComponentPurl),
	}, nil
}

func (s *Server) importUploadedVEXStatements(r *http.Request, tx *sql.Tx, queries *store.Queries, ctx uploadedVEXImportContext, statements []vex.Statement) ([]uploadedVEXStatementScope, error) {
	scopes := make([]uploadedVEXStatementScope, 0, len(statements))
	for index, statement := range statements {
		scope, err := s.importUploadedVEXStatement(r, tx, queries, ctx, statement, index)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
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
		sourceDocumentURL: resolveUploadedVEXSourceDocumentURL(artifact, content),
	}
	scopes, err := s.importUploadedVEXStatements(r, tx, queries, importCtx, statements)
	if err != nil {
		return err
	}
	if err := pruneImportedVEXStatements(r.Context(), tx, importCtx, scopes); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func upsertImportedVEXStatement(ctx context.Context, tx *sql.Tx, params dbgen.CreateVEXStatementParams) error {
	var statementID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		INSERT INTO vex_statements (
			org_id,
			advisory_id,
			repo_id,
			component_purl,
			status,
			justification,
			impact_statement,
			action_statement,
			source,
			source_document_url,
			supplier,
			created_by,
			expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (
			org_id,
			advisory_id,
			COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::UUID),
			COALESCE(component_purl, '')
		) DO UPDATE
		SET
			repo_id = EXCLUDED.repo_id,
			component_purl = EXCLUDED.component_purl,
			status = EXCLUDED.status,
			justification = EXCLUDED.justification,
			impact_statement = EXCLUDED.impact_statement,
			action_statement = EXCLUDED.action_statement,
			source = EXCLUDED.source,
			source_document_url = EXCLUDED.source_document_url,
			supplier = EXCLUDED.supplier,
			created_by = EXCLUDED.created_by,
			expires_at = EXCLUDED.expires_at,
			updated_at = CASE
				WHEN vex_statements.repo_id IS DISTINCT FROM EXCLUDED.repo_id
					OR vex_statements.component_purl IS DISTINCT FROM EXCLUDED.component_purl
					OR vex_statements.status IS DISTINCT FROM EXCLUDED.status
					OR vex_statements.justification IS DISTINCT FROM EXCLUDED.justification
					OR vex_statements.impact_statement IS DISTINCT FROM EXCLUDED.impact_statement
					OR vex_statements.action_statement IS DISTINCT FROM EXCLUDED.action_statement
					OR vex_statements.source IS DISTINCT FROM EXCLUDED.source
					OR vex_statements.source_document_url IS DISTINCT FROM EXCLUDED.source_document_url
					OR vex_statements.supplier IS DISTINCT FROM EXCLUDED.supplier
					OR vex_statements.created_by IS DISTINCT FROM EXCLUDED.created_by
					OR vex_statements.expires_at IS DISTINCT FROM EXCLUDED.expires_at
				THEN NOW()
				ELSE vex_statements.updated_at
			END
		WHERE vex_statements.source = 'imported'
		RETURNING id
	`,
		params.OrgID,
		params.AdvisoryID,
		params.RepoID,
		params.ComponentPurl,
		params.Status,
		params.Justification,
		params.ImpactStatement,
		params.ActionStatement,
		params.Source,
		params.SourceDocumentUrl,
		params.Supplier,
		params.CreatedBy,
		params.ExpiresAt,
	).Scan(&statementID)
	if errors.Is(err, sql.ErrNoRows) {
		return errConflict("conflicting non-imported VEX statement already exists for this advisory/component scope")
	}
	return err
}

func pruneImportedVEXStatements(ctx context.Context, tx *sql.Tx, importCtx uploadedVEXImportContext, scopes []uploadedVEXStatementScope) error {
	advisoryIDs := make([]uuid.UUID, len(scopes))
	componentPURLs := make([]string, len(scopes))
	for i, scope := range scopes {
		advisoryIDs[i] = scope.advisoryID
		componentPURLs[i] = scope.componentPURL
	}

	_, err := tx.ExecContext(ctx, `
		WITH input_scopes AS (
			SELECT advisory_id, component_purl
			FROM unnest($3::uuid[], $4::text[]) AS scope(advisory_id, component_purl)
		)
		DELETE FROM vex_statements v
		WHERE v.org_id = $1
		  AND v.repo_id = $2
		  AND v.source = 'imported'
		  AND v.source_document_url = $5
		  AND NOT EXISTS (
			SELECT 1
			FROM input_scopes s
			WHERE s.advisory_id = v.advisory_id
			  AND s.component_purl = COALESCE(v.component_purl, '')
		  )
	`, importCtx.orgID, importCtx.repoID, pq.Array(advisoryIDs), pq.Array(componentPURLs), importCtx.sourceDocumentURL)
	return err
}

func vexScopeComponentPURL(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
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
	input.RunID = strings.TrimSpace(input.RunID)
	input.RunAttempt = strings.TrimSpace(input.RunAttempt)
	input.RunNumber = strings.TrimSpace(input.RunNumber)
	input.BuildURL = strings.TrimSpace(input.BuildURL)
	input.PRNumber = strings.TrimSpace(input.PRNumber)
	input.PRTargetBranch = strings.TrimSpace(input.PRTargetBranch)
	input.PRSourceBranch = strings.TrimSpace(input.PRSourceBranch)
	input.PRTitle = strings.TrimSpace(input.PRTitle)
	input.Tag = strings.TrimSpace(input.Tag)
}

func buildUploadRefOptions(input uploadRequest) store.UpsertRefOptions {
	refType := refTypeFromName(input.Ref)
	options := store.UpsertRefOptions{
		LatestCommitSHA: &input.CommitSHA,
		PRTitle:         input.PRTitle,
		PRSourceBranch:  input.PRSourceBranch,
	}
	if refType != store.RefTypePullRequest {
		return options
	}
	options.PRNumber = optionalTrimmedString(input.PRNumber)
	if options.PRNumber == nil {
		options.PRNumber = optionalTrimmedString(prNumberFromName(input.Ref))
	}
	return options
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
	if strings.HasPrefix(name, refsTagsPrefix) {
		return store.RefTypeTag
	}
	return store.RefTypeBranch
}

func prNumberFromName(name string) string {
	name = strings.TrimSpace(name)
	matches := prNumberPattern.FindStringSubmatch(name)
	if len(matches) != 3 {
		return ""
	}
	return matches[2]
}

func normalizeStoredRefName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, refsHeadsPrefix) {
		return strings.TrimPrefix(name, refsHeadsPrefix)
	}
	if strings.HasPrefix(name, refsTagsPrefix) {
		return strings.TrimPrefix(name, refsTagsPrefix)
	}
	// A pull request collapses to a single canonical ref (refs/pull/N), so the
	// /head and /merge variants both resolve to and store the same row.
	if m := prCanonicalPattern.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return name
}

func optionalTrimmedString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func resolveUploadTag(refName, explicitTag string) *string {
	if tag := optionalTrimmedString(explicitTag); tag != nil {
		return tag
	}
	if refTypeFromName(refName) != store.RefTypeTag {
		return nil
	}
	return optionalTrimmedString(normalizeStoredRefName(refName))
}

func positiveInt32Ptr(value *int) *int32 {
	if value == nil || *value <= 0 {
		return nil
	}
	if *value > math.MaxInt32 {
		result := int32(math.MaxInt32)
		return &result
	}
	result := int32(*value)
	return &result
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

type conflictError struct {
	message string
}

func (e conflictError) Error() string {
	return e.message
}

func errConflict(message string) error {
	return conflictError{message: message}
}

func (s *Server) writeUploadError(w http.ResponseWriter, err error) {
	if err == nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to process upload")
		return
	}

	var badRequest badRequestError
	var conflict conflictError
	var notFound notFoundError
	if ok := errorAsBadRequest(err, &badRequest); ok {
		api.JSONError(w, http.StatusBadRequest, badRequest.message)
		return
	}
	if ok := errorAsConflict(err, &conflict); ok {
		api.JSONError(w, http.StatusConflict, conflict.message)
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

func errorAsConflict(err error, target *conflictError) bool {
	return errors.As(err, target)
}

func errorAsNotFound(err error, target *notFoundError) bool {
	return errors.As(err, target)
}
