package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store"
)

// Release inventory sources (ADR-046 §4, ADR-045 §5.3): every artifact
// that reported components for the release's pinned snapshot, with its
// origin; deliverables the CLI analysed locally are recorded here,
// additively; an admin can revoke and restore a manual source.

type releaseSourceResponse struct {
	ID               uuid.UUID       `json:"id"`
	Filename         string          `json:"filename"`
	Tool             string          `json:"tool"`
	ToolVersion      string          `json:"tool_version,omitempty"`
	Origin           string          `json:"origin"`
	SHA256           string          `json:"sha256,omitempty"`
	ComponentCount   int             `json:"component_count"`
	CreatedAt        time.Time       `json:"created_at"`
	CreatedBy        *uuid.UUID      `json:"created_by,omitempty"`
	AfterRelease     bool            `json:"after_release"`
	Revoked          bool            `json:"revoked"`
	RevokedAt        *time.Time      `json:"revoked_at,omitempty"`
	RevokeReason     string          `json:"revoke_reason,omitempty"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
	ExtractorVersion string          `json:"extractor_version,omitempty"`
}

type releaseSourcesResponse struct {
	Sources    []releaseSourceResponse `json:"sources"`
	Components []struct {
		Purl    string `json:"purl"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
	CurrentExtractorVersion string `json:"current_extractor_version"`
	RecordCommand           string `json:"record_command"`
	CanRevoke               bool   `json:"can_revoke"`
}

// handleListReleaseSources lists the release's inventory sources.
func (s *Server) handleListReleaseSources(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	release, ok := s.loadReleaseByParam(w, r, repo)
	if !ok {
		return
	}
	response := releaseSourcesResponse{
		Sources:                 []releaseSourceResponse{},
		CurrentExtractorVersion: depinventory.Version,
		RecordCommand:           fmt.Sprintf("hibou release scan %s <FILES...> --org %s/%s --repo %s", release.Version, org.Provider, org.Slug, repo.Slug),
		CanRevoke:               s.isAdminUserSession(r, org.ID),
	}
	if release.SnapshotID == nil {
		api.JSON(w, http.StatusOK, response)
		return
	}
	artifacts, err := s.queries.ListSnapshotArtifactsBySnapshot(r.Context(), *release.SnapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list release sources")
		return
	}
	releaseDate := release.CreatedAt
	if release.PublishedAt != nil {
		releaseDate = *release.PublishedAt
	}
	for _, artifact := range artifacts {
		if artifact.Kind != "sbom" {
			continue
		}
		entry := releaseSourceResponse{
			ID: artifact.ID, Filename: artifact.Filename, Origin: artifact.Origin, CreatedAt: artifact.CreatedAt, CreatedBy: artifact.CreatedBy,
			AfterRelease: artifact.CreatedAt.After(releaseDate.Add(time.Hour)),
			Revoked:      artifact.RevokedAt != nil, RevokedAt: artifact.RevokedAt, Metadata: artifact.Metadata,
		}
		if artifact.ToolName != nil {
			entry.Tool = *artifact.ToolName
		}
		if artifact.ToolVersion != nil {
			entry.ToolVersion = *artifact.ToolVersion
			if entry.Tool == depinventory.ToolName {
				entry.ExtractorVersion = *artifact.ToolVersion
			}
		}
		if artifact.SHA256 != nil {
			entry.SHA256 = *artifact.SHA256
		}
		if artifact.RevokeReason != nil {
			entry.RevokeReason = *artifact.RevokeReason
		}
		if entry.Origin == "" {
			entry.Origin = store.ArtifactOriginCI
			if artifact.Filename == depInventoryArtifactFilename {
				entry.Origin = store.ArtifactOriginServer
			}
		}
		if count, err := s.queries.CountSnapshotComponentsBySourceLabel(r.Context(), *release.SnapshotID, "sbom:"+artifact.Filename); err == nil {
			entry.ComponentCount = count
		}
		response.Sources = append(response.Sources, entry)
	}
	if components, err := s.queries.ListComponentsBySnapshot(r.Context(), *release.SnapshotID); err == nil {
		for _, component := range components {
			response.Components = append(response.Components, struct {
				Purl    string `json:"purl"`
				Name    string `json:"name"`
				Version string `json:"version"`
			}{component.Purl, component.Name, component.Version})
		}
	}
	api.JSON(w, http.StatusOK, response)
}

func (s *Server) loadReleaseByParam(w http.ResponseWriter, r *http.Request, repo *store.Repository) (*store.Release, bool) {
	releaseID, err := uuid.Parse(chi.URLParam(r, "releaseID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid release ID")
		return nil, false
	}
	release, err := s.queries.GetReleaseByRepoAndID(r.Context(), repo.ID, releaseID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load release")
		return nil, false
	}
	if release == nil {
		api.JSONError(w, http.StatusNotFound, "release not found")
		return nil, false
	}
	return release, true
}

// isAdminUserSession: revocation needs an admin in a user session (web UI
// or CLI browser login), never an automation token (ADR-046 §4.3, point 8).
func (s *Server) isAdminUserSession(r *http.Request, orgID uuid.UUID) bool {
	if UserFromContext(r.Context()) == nil {
		return false
	}
	role, err := s.principalOrgRole(r, orgID)
	return err == nil && role == "admin"
}

type recordReleaseSourceRequest struct {
	Filename      string          `json:"filename"`
	ContentBase64 string          `json:"content_base64"`
	CLIVersion    string          `json:"cli_version"`
	Extractor     string          `json:"extractor"`
	Deliverables  json.RawMessage `json:"deliverables"`
	Checks        []string        `json:"checks"`
	Problems      []string        `json:"problems"`
	Reason        string          `json:"reason"`
	Force         bool            `json:"force"`
}

// handleRecordReleaseSource records an inventory the CLI produced from
// deliverables: additive, idempotent by digest, bound to the release's
// snapshot, audit-logged. Release managers and admins, or a repository
// automation token.
func (s *Server) handleRecordReleaseSource(w http.ResponseWriter, r *http.Request) {
	org, repo, user, release, ok := s.loadReleaseForManager(w, r)
	if !ok {
		return
	}
	var req recordReleaseSourceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&req); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	document, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil || len(document) == 0 {
		api.JSONError(w, http.StatusBadRequest, "content_base64 is required")
		return
	}
	components, err := sbom.ParseCycloneDXJSON(document)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "the document is not CycloneDX JSON: "+err.Error())
		return
	}
	if len(req.Problems) > 0 && (!req.Force || strings.TrimSpace(req.Reason) == "") {
		api.JSONError(w, http.StatusConflict, "the deliverable does not match the release; record with force and a reason")
		return
	}
	if release.SnapshotID == nil {
		api.JSONError(w, http.StatusConflict, "the release has no analysed snapshot yet: extract its tag first (hibou release scan "+release.Version+")")
		return
	}
	snapshot, err := s.queries.GetSnapshotByID(r.Context(), *release.SnapshotID)
	if err != nil || snapshot == nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the release snapshot")
		return
	}
	filename := strings.TrimSpace(req.Filename)
	if filename == "" || strings.ContainsAny(filename, "/\\") {
		filename = "deliverables.cdx.json"
	}
	params := buildSnapshotArtifactParams(snapshot.ID, "sbom", "cyclonedx-json", depinventory.ToolName, filename, document)
	// Idempotent (point 5): a document already recorded is a no-op.
	existing, err := s.queries.ListSnapshotArtifactsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list release sources")
		return
	}
	for _, artifact := range existing {
		if artifact.SHA256 != nil && params.SHA256 != nil && *artifact.SHA256 == *params.SHA256 && artifact.RevokedAt == nil {
			api.JSON(w, http.StatusOK, map[string]any{"id": artifact.ID, "components": len(components), "duplicate": true})
			return
		}
		if artifact.Filename == filename {
			// Same name, other content: keep both, distinguishable.
			filename = strings.TrimSuffix(filename, ".cdx.json") + "-" + time.Now().UTC().Format("20060102T150405Z") + ".cdx.json"
			params = buildSnapshotArtifactParams(snapshot.ID, "sbom", "cyclonedx-json", depinventory.ToolName, filename, document)
		}
	}
	toolVersion := strings.TrimSpace(req.Extractor)
	if toolVersion == "" {
		toolVersion = depinventory.Version
	}
	artifactID, params, err := s.storeSBOMArtifact(r.Context(), snapshot.ID, params, document, toolVersion)
	if err != nil {
		s.log.Error().Err(err).Str("release_id", release.ID.String()).Msg("record release source")
		api.JSONError(w, http.StatusInternalServerError, "failed to store the inventory")
		return
	}
	var createdBy *uuid.UUID
	if user != nil {
		createdBy = &user.ID
	}
	metadata, _ := json.Marshal(map[string]any{
		"deliverables": req.Deliverables, "checks": req.Checks, "problems": req.Problems, "reason": strings.TrimSpace(req.Reason),
		"cli_version": req.CLIVersion, "extractor": toolVersion, "release": release.Version, "commit": release.ID,
	})
	if err := s.queries.SetSnapshotArtifactSource(r.Context(), *artifactID, store.ArtifactOriginManual, createdBy, metadata); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the source")
		return
	}
	if err := s.ingestInventoryNow(r.Context(), snapshot, artifactID, params, document); err != nil {
		s.log.Error().Err(err).Str("artifact_id", artifactID.String()).Msg("ingest release source")
		api.JSONError(w, http.StatusInternalServerError, "failed to ingest the inventory")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionReleaseSourceAdded, ResourceType: "release", ResourceID: release.ID.String(), Context: map[string]any{
		"repo": repo.Slug, "release": release.Version, "artifact_id": artifactID.String(), "filename": filename, "sha256": derefString(params.SHA256), "components": len(components), "forced": req.Force, "reason": strings.TrimSpace(req.Reason),
	}})
	api.JSON(w, http.StatusCreated, map[string]any{"id": artifactID, "components": len(components), "duplicate": false})
}

// storeSBOMArtifact stores one SBOM document as a snapshot artifact and
// records its run declaration; the caller ingests it.
func (s *Server) storeSBOMArtifact(ctx context.Context, snapshotID uuid.UUID, params store.CreateSnapshotArtifactParams, document []byte, toolVersion string) (*uuid.UUID, store.CreateSnapshotArtifactParams, error) {
	contentType := ""
	if params.ContentType != nil {
		contentType = *params.ContentType
	}
	if err := s.objStore.Put(ctx, params.ObjectKey, bytes.NewReader(document), contentType); err != nil {
		return nil, params, fmt.Errorf("store inventory document: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, params, err
	}
	defer func() { _ = tx.Rollback() }()
	queries := s.queries.WithTx(tx)
	if err := queries.LockSnapshotForUpdate(ctx, snapshotID); err != nil {
		return nil, params, err
	}
	created, err := queries.CreateSnapshotArtifact(ctx, params)
	if err != nil {
		return nil, params, fmt.Errorf("record inventory artifact: %w", err)
	}
	if created == nil {
		return nil, params, errors.New("record inventory artifact: no row")
	}
	if err := queries.AddSnapshotArtifactBytes(ctx, snapshotID, params.SizeBytes); err != nil {
		return nil, params, err
	}
	scope := store.ProducerScopeFull
	if err := queries.SetSnapshotArtifactRunDeclaration(ctx, created.ID, store.ArtifactRunDeclaration{Scope: &scope, ToolVersion: &toolVersion}); err != nil {
		return nil, params, err
	}
	if err := tx.Commit(); err != nil {
		return nil, params, err
	}
	id := created.ID
	return &id, params, nil
}

type releaseSourceActionRequest struct {
	Reason string `json:"reason"`
}

// handleRevokeReleaseSource removes a manual source from the effective
// inventory (ADR-045 §5.3): the artifact stays, its components leave
// unless another source reports them, and the snapshot is rescanned.
func (s *Server) handleRevokeReleaseSource(w http.ResponseWriter, r *http.Request) {
	s.releaseSourceAction(w, r, "revoke")
}

// handleRestoreReleaseSource lifts a revocation and re-ingests the
// artifact's document.
func (s *Server) handleRestoreReleaseSource(w http.ResponseWriter, r *http.Request) {
	s.releaseSourceAction(w, r, "restore")
}

func (s *Server) releaseSourceAction(w http.ResponseWriter, r *http.Request, action string) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.isAdminUserSession(r, org.ID) {
		api.JSONError(w, http.StatusForbidden, "an organization admin in a user session is required; automation tokens cannot revoke or restore sources")
		return
	}
	user := UserFromContext(r.Context())
	release, ok := s.loadReleaseByParam(w, r, repo)
	if !ok {
		return
	}
	sourceID, err := uuid.Parse(chi.URLParam(r, "sourceID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid source ID")
		return
	}
	artifact, err := s.queries.GetSnapshotArtifactByID(r.Context(), sourceID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the source")
		return
	}
	if artifact == nil || release.SnapshotID == nil || artifact.SnapshotID != *release.SnapshotID || artifact.Kind != "sbom" {
		api.JSONError(w, http.StatusNotFound, "source not found on this release")
		return
	}
	if artifact.Origin != store.ArtifactOriginManual {
		api.JSONError(w, http.StatusConflict, "build-time sources cannot be revoked; only deliverables recorded with hibou release scan can")
		return
	}
	var req releaseSourceActionRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	snapshot, err := s.queries.GetSnapshotByID(r.Context(), artifact.SnapshotID)
	if err != nil || snapshot == nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the release snapshot")
		return
	}
	label := "sbom:" + artifact.Filename
	switch action {
	case "revoke":
		if strings.TrimSpace(req.Reason) == "" {
			api.JSONError(w, http.StatusBadRequest, "a reason is required")
			return
		}
		done, err := s.queries.RevokeSnapshotArtifact(r.Context(), artifact.ID, &user.ID, strings.TrimSpace(req.Reason))
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to revoke the source")
			return
		}
		if !done {
			api.JSONError(w, http.StatusConflict, "the source is already revoked")
			return
		}
		removed, err := s.queries.RemoveSnapshotComponentSource(r.Context(), snapshot.ID, label)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to remove the source's components")
			return
		}
		s.enqueueAdvisoryScan(snapshot.ID, "release-source-revoked")
		s.refreshScanCoverageForSnapshot(r.Context(), snapshot.ID)
		s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionReleaseSourceRevoked, ResourceType: "release", ResourceID: release.ID.String(), Context: map[string]any{"repo": repo.Slug, "release": release.Version, "artifact_id": artifact.ID.String(), "filename": artifact.Filename, "reason": strings.TrimSpace(req.Reason), "components_removed": removed}})
		api.JSON(w, http.StatusOK, map[string]any{"revoked": true, "components_removed": removed})
	case "restore":
		done, err := s.queries.RestoreSnapshotArtifact(r.Context(), artifact.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to restore the source")
			return
		}
		if !done {
			api.JSONError(w, http.StatusConflict, "the source is not revoked")
			return
		}
		loaded, err := s.loadSnapshotArtifact(r.Context(), *artifact)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to read the source document")
			return
		}
		params := store.CreateSnapshotArtifactParams{SnapshotID: snapshot.ID, Kind: artifact.Kind, Format: artifact.Format, ToolName: artifact.ToolName, ObjectKey: artifact.ObjectKey, SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes, ContentType: artifact.ContentType, Filename: artifact.Filename}
		if err := s.ingestInventoryNow(r.Context(), snapshot, &artifact.ID, params, loaded.content); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to re-ingest the source")
			return
		}
		s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionReleaseSourceRestored, ResourceType: "release", ResourceID: release.ID.String(), Context: map[string]any{"repo": repo.Slug, "release": release.Version, "artifact_id": artifact.ID.String(), "filename": artifact.Filename}})
		api.JSON(w, http.StatusOK, map[string]any{"restored": true})
	}
}
