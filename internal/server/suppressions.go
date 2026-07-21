package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/vex"
)

type createVEXStatementRequest struct {
	VulnerabilityID   string     `json:"vulnerability_id"`
	Status            string     `json:"status"`
	Justification     string     `json:"justification"`
	ImpactStatement   string     `json:"impact_statement"`
	ActionStatement   string     `json:"action_statement"`
	ComponentPURL     string     `json:"component_purl"`
	Source            string     `json:"source"`
	SourceDocumentURL string     `json:"source_document_url"`
	Supplier          string     `json:"supplier"`
	ExpiresAt         *time.Time `json:"expires_at"`
}

type updateVEXStatementRequest struct {
	Status            string     `json:"status"`
	Justification     string     `json:"justification"`
	ImpactStatement   string     `json:"impact_statement"`
	ActionStatement   string     `json:"action_statement"`
	ComponentPURL     string     `json:"component_purl"`
	Source            string     `json:"source"`
	SourceDocumentURL string     `json:"source_document_url"`
	Supplier          string     `json:"supplier"`
	ExpiresAt         *time.Time `json:"expires_at"`
}

func (s *Server) handleCreateVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var input createVEXStatementRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	advisory, err := s.resolveVEXAdvisory(r.Context(), input.VulnerabilityID)
	if err != nil {
		s.handleVEXLookupError(w, err)
		return
	}
	params, err := buildCreateVEXParams(org.ID, repo.ID, user.ID, advisory.ID, input)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	statement, err := s.queries.CreateVEXStatement(r.Context(), params)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create VEX statement")
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, statement.ID, audit.ActionVEXCreate, map[string]any{
		"repo_id":          repo.ID,
		"advisory_id":      advisory.ID,
		"vulnerability_id": advisory.CanonicalID,
		"status":           statement.Status,
	})

	// A VEX statement (e.g. dismissing a false positive) changes the PR delta, so
	// re-evaluate and re-post the forge gate check for the repo's open PRs — no CI
	// re-run required. See ADR-018.
	s.publishGateRecompute(r.Context(), repo.ID)

	api.JSON(w, http.StatusCreated, statement)
}

func (s *Server) handleListVEXStatements(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	rows, err := s.queries.ListVEXStatementsByRepo(r.Context(), dbgen.ListVEXStatementsByRepoParams{
		OrgID:  org.ID,
		RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true},
		Limit:  int32(pagination.PerPage), //nolint:gosec // G115: pagination is bounded by API parsing.
		Offset: int32(pagination.Offset),  //nolint:gosec // G115: pagination is bounded by API parsing.
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list VEX statements")
		return
	}
	total, err := s.queries.CountVEXStatementsByRepo(r.Context(), dbgen.CountVEXStatementsByRepoParams{
		OrgID:  org.ID,
		RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true},
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to count VEX statements")
		return
	}

	api.JSONList(w, rows, pagination.Page, pagination.PerPage, int(total))
}

func (s *Server) handleGetVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	statement, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}

	api.JSON(w, http.StatusOK, statement)
}

func (s *Server) handleUpdateVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}

	var input updateVEXStatementRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	params, err := buildUpdateVEXParams(existing.ID, org.ID, repo.ID, input)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	statement, err := s.queries.UpdateVEXStatement(r.Context(), params)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update VEX statement")
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, statement.ID, audit.ActionVEXUpdate, map[string]any{
		"repo_id": repo.ID,
		"status":  statement.Status,
	})

	s.publishGateRecompute(r.Context(), repo.ID)

	api.JSON(w, http.StatusOK, statement)
}

func (s *Server) handleDeleteVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	statement, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}
	if err := s.queries.DeleteVEXStatement(r.Context(), dbgen.DeleteVEXStatementParams{ID: statement.ID, OrgID: org.ID}); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete VEX statement")
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, statement.ID, audit.ActionVEXRevoke, map[string]any{
		"repo_id": repo.ID,
	})

	s.publishGateRecompute(r.Context(), repo.ID)

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleExportVEX(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = vex.FormatOpenVEX
	}
	if format != vex.FormatOpenVEX && format != vex.FormatCSAF {
		api.JSONError(w, http.StatusBadRequest, "format must be openvex or csaf")
		return
	}

	total, err := s.queries.CountVEXStatementsByRepo(r.Context(), dbgen.CountVEXStatementsByRepoParams{
		OrgID:  org.ID,
		RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true},
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to count VEX statements")
		return
	}
	rows, err := s.queries.ListVEXStatementsByRepo(r.Context(), dbgen.ListVEXStatementsByRepoParams{
		OrgID:  org.ID,
		RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true},
		Limit:  int32(total), //nolint:gosec // G115: total row count is bounded by repository statement volume.
		Offset: 0,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list VEX statements")
		return
	}

	payload, err := s.exportVEXDocument(r.Context(), rows, org, user, format)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to export VEX document")
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, uuid.Nil, audit.ActionVEXExport, map[string]any{
		"repo_id": repo.ID,
		"format":  format,
		"count":   len(rows),
	})

	api.JSON(w, http.StatusOK, json.RawMessage(payload))
}

func (s *Server) loadVEXStatement(r *http.Request, w http.ResponseWriter, orgID, repoID uuid.UUID) (dbgen.VexStatement, bool) {
	statementID, err := parseUUIDParam(r, "statementID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid statement ID")
		return dbgen.VexStatement{}, false
	}
	statement, err := s.queries.GetVEXStatementByID(r.Context(), statementID)
	if errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "VEX statement not found")
		return dbgen.VexStatement{}, false
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load VEX statement")
		return dbgen.VexStatement{}, false
	}
	if statement.OrgID != orgID {
		api.JSONError(w, http.StatusNotFound, "VEX statement not found")
		return dbgen.VexStatement{}, false
	}
	if statement.RepoID.Valid && statement.RepoID.UUID != repoID {
		api.JSONError(w, http.StatusNotFound, "VEX statement not found")
		return dbgen.VexStatement{}, false
	}
	return statement, true
}

func buildCreateVEXParams(orgID, repoID, userID, advisoryID uuid.UUID, input createVEXStatementRequest) (dbgen.CreateVEXStatementParams, error) {
	status, justification, source, componentPURL, expiresAt, err := normalizeVEXFields(input.Status, input.Justification, input.Source, input.ComponentPURL, input.ExpiresAt)
	if err != nil {
		return dbgen.CreateVEXStatementParams{}, err
	}
	return dbgen.CreateVEXStatementParams{
		OrgID:             orgID,
		AdvisoryID:        advisoryID,
		RepoID:            uuid.NullUUID{UUID: repoID, Valid: true},
		ComponentPurl:     componentPURL,
		Status:            status,
		Justification:     justification,
		ImpactStatement:   strings.TrimSpace(input.ImpactStatement),
		ActionStatement:   strings.TrimSpace(input.ActionStatement),
		Source:            source,
		SourceDocumentUrl: strings.TrimSpace(input.SourceDocumentURL),
		Supplier:          strings.TrimSpace(input.Supplier),
		CreatedBy:         uuid.NullUUID{UUID: userID, Valid: true},
		ExpiresAt:         expiresAt,
	}, nil
}

func buildUpdateVEXParams(statementID, orgID, repoID uuid.UUID, input updateVEXStatementRequest) (dbgen.UpdateVEXStatementParams, error) {
	status, justification, source, componentPURL, expiresAt, err := normalizeVEXFields(input.Status, input.Justification, input.Source, input.ComponentPURL, input.ExpiresAt)
	if err != nil {
		return dbgen.UpdateVEXStatementParams{}, err
	}
	return dbgen.UpdateVEXStatementParams{
		RepoID:            uuid.NullUUID{UUID: repoID, Valid: true},
		ComponentPurl:     componentPURL,
		Status:            status,
		Justification:     justification,
		ImpactStatement:   strings.TrimSpace(input.ImpactStatement),
		ActionStatement:   strings.TrimSpace(input.ActionStatement),
		Source:            source,
		SourceDocumentUrl: strings.TrimSpace(input.SourceDocumentURL),
		Supplier:          strings.TrimSpace(input.Supplier),
		ExpiresAt:         expiresAt,
		ID:                statementID,
		OrgID:             orgID,
	}, nil
}

func normalizeVEXFields(statusRaw, justificationRaw, sourceRaw, componentPURLRaw string, expiresAt *time.Time) (dbgen.VexStatus, dbgen.NullVexJustification, dbgen.VexSource, sql.NullString, sql.NullTime, error) {
	status, ok := parseVEXStatus(statusRaw)
	if !ok {
		return "", dbgen.NullVexJustification{}, "", sql.NullString{}, sql.NullTime{}, errors.New("invalid VEX status")
	}
	justification, err := parseVEXJustification(justificationRaw, status)
	if err != nil {
		return "", dbgen.NullVexJustification{}, "", sql.NullString{}, sql.NullTime{}, err
	}
	source, ok := parseVEXSource(sourceRaw)
	if !ok {
		return "", dbgen.NullVexJustification{}, "", sql.NullString{}, sql.NullTime{}, errors.New("invalid VEX source")
	}
	componentPURL := strings.TrimSpace(componentPURLRaw)
	return status, justification, source, sql.NullString{String: componentPURL, Valid: componentPURL != ""}, nullTimePtr(expiresAt), nil
}

func parseVEXStatus(value string) (dbgen.VexStatus, bool) {
	switch strings.TrimSpace(value) {
	case vex.StatusNotAffected:
		return dbgen.VexStatusNotAffected, true
	case vex.StatusAffected:
		return dbgen.VexStatusAffected, true
	case vex.StatusFixed:
		return dbgen.VexStatusFixed, true
	case vex.StatusUnderInvestigation:
		return dbgen.VexStatusUnderInvestigation, true
	default:
		return "", false
	}
}

func parseVEXSource(value string) (dbgen.VexSource, bool) {
	source := strings.TrimSpace(value)
	if source == "" {
		source = vex.SourceManual
	}
	switch source {
	case vex.SourceManual:
		return dbgen.VexSourceManual, true
	case vex.SourceImported:
		return dbgen.VexSourceImported, true
	case vex.SourcePropagated:
		return dbgen.VexSourcePropagated, true
	case vex.SourceAutomated:
		return dbgen.VexSourceAutomated, true
	default:
		return "", false
	}
}

func parseVEXJustification(value string, status dbgen.VexStatus) (dbgen.NullVexJustification, error) {
	trimmed := strings.TrimSpace(value)
	if status != dbgen.VexStatusNotAffected {
		return dbgen.NullVexJustification{}, nil
	}
	if trimmed == "" {
		return dbgen.NullVexJustification{}, errors.New("justification is required when status is not_affected")
	}
	switch trimmed {
	case vex.JustComponentNotPresent:
		return dbgen.NullVexJustification{VexJustification: dbgen.VexJustificationComponentNotPresent, Valid: true}, nil
	case vex.JustVulnerableCodeNotPresent:
		return dbgen.NullVexJustification{VexJustification: dbgen.VexJustificationVulnerableCodeNotPresent, Valid: true}, nil
	case vex.JustCodeNotInExecutePath:
		return dbgen.NullVexJustification{VexJustification: dbgen.VexJustificationVulnerableCodeNotInExecutePath, Valid: true}, nil
	case vex.JustCodeCannotBeControlled:
		return dbgen.NullVexJustification{VexJustification: dbgen.VexJustificationVulnerableCodeCannotBeControlledByAdversary, Valid: true}, nil
	case vex.JustInlineMitigationsExist:
		return dbgen.NullVexJustification{VexJustification: dbgen.VexJustificationInlineMitigationsAlreadyExist, Valid: true}, nil
	default:
		return dbgen.NullVexJustification{}, errors.New("invalid VEX justification")
	}
}

func (s *Server) resolveVEXAdvisory(ctx context.Context, vulnerabilityID string) (dbgen.Advisory, error) {
	return resolveVEXAdvisoryWithQueries(ctx, s.queries, vulnerabilityID)
}

func resolveVEXAdvisoryWithQueries(ctx context.Context, queries *store.Queries, vulnerabilityID string) (dbgen.Advisory, error) {
	trimmed := strings.TrimSpace(vulnerabilityID)
	if trimmed == "" {
		return dbgen.Advisory{}, errors.New("vulnerability_id is required")
	}
	advisory, err := queries.GetAdvisoryByCanonicalID(ctx, trimmed)
	if err == nil {
		return advisory, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return dbgen.Advisory{}, err
	}
	advisory, err = queries.GetAdvisoryByAlias(ctx, trimmed)
	if err != nil {
		return dbgen.Advisory{}, err
	}
	return advisory, nil
}

func (s *Server) handleVEXLookupError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "advisory not found")
		return
	}
	if err.Error() == "vulnerability_id is required" {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	api.JSONError(w, http.StatusInternalServerError, "failed to resolve advisory")
}

func (s *Server) exportVEXDocument(ctx context.Context, rows []dbgen.VexStatement, org *store.Organization, user *store.User, format string) ([]byte, error) {
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.AdvisoryID)
	}
	advisories, err := s.queries.GetAdvisoriesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	advisoryByID := make(map[uuid.UUID]dbgen.Advisory, len(advisories))
	for _, advisory := range advisories {
		advisoryByID[advisory.ID] = advisory
	}
	statements := make([]vex.Statement, 0, len(rows))
	for _, row := range rows {
		advisory, ok := advisoryByID[row.AdvisoryID]
		if !ok {
			continue
		}
		statement := vex.Statement{
			VulnerabilityID:   advisory.CanonicalID,
			Status:            string(row.Status),
			ImpactStatement:   row.ImpactStatement,
			ActionStatement:   row.ActionStatement,
			Supplier:          row.Supplier,
			SourceDocumentURL: row.SourceDocumentUrl,
		}
		if row.ComponentPurl.Valid {
			statement.ComponentPURL = row.ComponentPurl.String
		}
		if row.Justification.Valid {
			statement.Justification = string(row.Justification.VexJustification)
		}
		statements = append(statements, statement)
	}
	meta := vex.ExportMeta{
		Author: actorDisplay(user),
		Publisher: vex.ExportPublisher{
			Category:  "tool",
			Name:      org.DisplayName,
			Namespace: s.vexPublisherNamespace(org),
		},
		DocumentID: fmt.Sprintf("%s-%s-vex", org.Slug, time.Now().UTC().Format("20060102150405")),
		TrackingID: fmt.Sprintf("%s-%s-csaf", org.Slug, time.Now().UTC().Format("20060102150405")),
		TLPLabel:   "TLP:CLEAR",
		Timestamp:  time.Now().UTC(),
	}
	if strings.TrimSpace(meta.Publisher.Name) == "" {
		meta.Publisher.Name = org.Name
	}
	switch format {
	case vex.FormatCSAF:
		return vex.ExportCSAF(statements, meta)
	default:
		return vex.ExportOpenVEX(statements, meta)
	}
}

func (s *Server) vexPublisherNamespace(org *store.Organization) string {
	baseURL := strings.TrimSpace(s.cfg.BaseURL)
	if baseURL != "" {
		return strings.TrimRight(baseURL, "/") + "/orgs/" + org.Provider + "/" + org.Slug
	}
	return fmt.Sprintf("https://example.invalid/orgs/%s/%s", org.Provider, org.Slug)
}

func (s *Server) writeVEXAuditLog(r *http.Request, user *store.User, orgID, statementID uuid.UUID, action string, context map[string]any) {
	contextBody, err := json.Marshal(context)
	if err != nil {
		contextBody = json.RawMessage(`{"status":"marshal_error"}`)
	}
	ipAddress, userAgent := audit.RequestContext(r)
	_, _ = s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID:      uuid.NullUUID{UUID: user.ID, Valid: true},
		ActorType:    audit.ActorUser,
		ActorDisplay: actorDisplay(user),
		Action:       action,
		ResourceType: "vex_statement",
		ResourceID:   statementID.String(),
		OrgID:        uuid.NullUUID{UUID: orgID, Valid: true},
		Context:      contextBody,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
	})
}

func nullTimePtr(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}
