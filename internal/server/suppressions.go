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
	"github.com/hibouhq/hibou/internal/incident"
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
	// ReleaseID or VersionRange (a vers range) narrow the statement to
	// shipped versions (ADR-053 §4a); neither means the whole repository.
	ReleaseID    string          `json:"release_id,omitempty"`
	VersionRange string          `json:"version_range,omitempty"`
	Evidence     json.RawMessage `json:"evidence,omitempty" swaggertype:"object"`
}

// updateVEXStatementRequest revises a statement; vulnerability_id is ignored
// (a revision keeps the advisory).
type updateVEXStatementRequest createVEXStatementRequest

func (s *Server) handleCreateVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())

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
	actorID := uuid.Nil
	if user != nil {
		actorID = user.ID
	}
	params, err := buildCreateVEXParams(org.ID, repo.ID, actorID, advisory.ID, input)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyVEXProductAxis(r.Context(), repo.ID, input.ReleaseID, input.VersionRange, &params); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(input.Evidence) > 0 {
		params.Evidence = input.Evidence
	}
	s.applyVEXApprovalPolicy(r.Context(), org.ID, &params)

	statement, err := s.queries.RecordVEXStatement(r.Context(), params)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusConflict, "another statement was recorded for this scope meanwhile; reload and retry")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create VEX statement")
		return
	}
	s.queueIncidentReconcileForAdvisory(r.Context(), org.ID, statement.AdvisoryID)

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
		Limit:  int32(pagination.PerPage), // #nosec G115 -- pagination is bounded by API parsing.
		Offset: int32(pagination.Offset),  // #nosec G115 -- pagination is bounded by API parsing.
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

// handleUpdateVEXStatement revises a statement (ADR-053 §4a): the revision is
// a new row that supersedes the current one; the old row keeps its content.
// A revision that moves the statement to another scope withdraws the old
// scope's statement and records the new one.
func (s *Server) handleUpdateVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())

	existing, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}
	if existing.SupersededAt.Valid || existing.Withdrawn {
		api.JSONError(w, http.StatusConflict, "this statement was already revised or withdrawn; revise the current one")
		return
	}

	var input updateVEXStatementRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	actorID := uuid.Nil
	if user != nil {
		actorID = user.ID
	}
	params, err := buildCreateVEXParams(org.ID, repo.ID, actorID, existing.AdvisoryID, createVEXStatementRequest(input))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyVEXProductAxis(r.Context(), repo.ID, input.ReleaseID, input.VersionRange, &params); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	params.Evidence = existing.Evidence
	s.applyVEXApprovalPolicy(r.Context(), org.ID, &params)

	sameScope := existing.ComponentPurl == params.ComponentPurl && existing.ReleaseID == params.ReleaseID && existing.VersionRange == params.VersionRange && existing.RepoID == params.RepoID
	if !sameScope {
		if _, err := s.queries.WithdrawVEXStatement(r.Context(), org.ID, existing.ID, params.CreatedBy); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to withdraw the previous statement")
			return
		}
	}
	statement, err := s.queries.RecordVEXStatement(r.Context(), params)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusConflict, "another statement was recorded for this scope meanwhile; reload and retry")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to record VEX statement")
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, statement.ID, audit.ActionVEXUpdate, map[string]any{
		"repo_id":    repo.ID,
		"status":     statement.Status,
		"supersedes": existing.ID,
	})
	s.publishGateRecompute(r.Context(), repo.ID)
	s.queueIncidentReconcileForAdvisory(r.Context(), org.ID, statement.AdvisoryID)

	api.JSON(w, http.StatusOK, statement)
}

// handleDeleteVEXStatement withdraws a statement: a withdrawn row becomes the
// scope's current one, and the history keeps everything that was said.
func (s *Server) handleDeleteVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())

	statement, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}
	actor := uuid.NullUUID{}
	if user != nil {
		actor = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	if _, err := s.queries.WithdrawVEXStatement(r.Context(), org.ID, statement.ID, actor); err != nil {
		if errors.Is(err, store.ErrVEXStatementNotCurrent) {
			api.JSONError(w, http.StatusConflict, "this statement was already revised or withdrawn")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to withdraw VEX statement")
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, statement.ID, audit.ActionVEXRevoke, map[string]any{
		"repo_id": repo.ID,
	})
	s.publishGateRecompute(r.Context(), repo.ID)
	s.queueIncidentReconcileForAdvisory(r.Context(), org.ID, statement.AdvisoryID)

	w.WriteHeader(http.StatusNoContent)
}

// handleGetVEXStatementHistory returns the chain a statement belongs to.
func (s *Server) handleGetVEXStatementHistory(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	statement, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}
	history, err := s.queries.ListVEXStatementHistory(r.Context(), org.ID, statement.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load statement history")
		return
	}
	api.JSON(w, http.StatusOK, history)
}

// handleApproveVEXStatement records a second person's approval, required when
// the organisation asks for it before a statement counts for an incident.
func (s *Server) handleApproveVEXStatement(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireReleaseManager(r, w, org.ID) {
		return
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusForbidden, "approval needs a person")
		return
	}
	statement, ok := s.loadVEXStatement(r, w, org.ID, repo.ID)
	if !ok {
		return
	}
	if statement.CreatedBy.Valid && statement.CreatedBy.UUID == user.ID {
		api.JSONError(w, http.StatusForbidden, "a statement is approved by someone other than its author")
		return
	}
	approved, err := s.queries.ApproveVEXStatement(r.Context(), org.ID, statement.ID, user.ID)
	if err != nil {
		if errors.Is(err, store.ErrVEXStatementNotCurrent) {
			api.JSONError(w, http.StatusConflict, "only the current statement can be approved")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to approve VEX statement")
		return
	}
	s.writeVEXAuditLog(r, user, org.ID, approved.ID, audit.ActionVEXApprove, map[string]any{"repo_id": repo.ID, "supersedes": statement.ID})
	s.queueIncidentReconcileForAdvisory(r.Context(), org.ID, approved.AdvisoryID)
	api.JSON(w, http.StatusOK, approved)
}

// handleExportVEX renders the repository's current statements on the fly
// (ADR-053 §5): OpenVEX, CycloneDX or CSAF. The statements table is the only
// source; documents sent to clients are stored separately, as sent.
func (s *Server) handleExportVEX(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	user := UserFromContext(r.Context())

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = vex.FormatOpenVEX
	}
	if format != vex.FormatOpenVEX && format != vex.FormatCSAF && format != vex.FormatCycloneDX {
		api.JSONError(w, http.StatusBadRequest, "format must be openvex, cyclonedx or csaf")
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
		Limit:  int32(total), // #nosec G115 -- total row count is bounded by repository statement volume.
		Offset: 0,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list VEX statements")
		return
	}

	now := time.Now().UTC()
	statements, err := s.vexStatementsForExport(r.Context(), org, repo, rows)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve VEX statements")
		return
	}
	meta := s.vexExportMeta(org, user, fmt.Sprintf("%s-%s-%s", org.Slug, repo.Slug, now.Format("20060102150405")), now)
	payload, err := renderVEX(format, statements, meta)
	if err != nil {
		api.JSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	s.writeVEXAuditLog(r, user, org.ID, uuid.Nil, audit.ActionVEXExport, map[string]any{
		"repo_id": repo.ID,
		"format":  format,
		"count":   len(rows),
	})

	api.JSON(w, http.StatusOK, json.RawMessage(payload))
}

func renderVEX(format string, statements []vex.Statement, meta vex.ExportMeta) ([]byte, error) {
	switch format {
	case vex.FormatCSAF:
		return vex.ExportCSAF(statements, meta)
	case vex.FormatCycloneDX:
		return vex.ExportCycloneDX(statements, meta)
	default:
		return vex.ExportOpenVEX(statements, meta)
	}
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
		CreatedBy:         uuid.NullUUID{UUID: userID, Valid: userID != uuid.Nil},
		ExpiresAt:         expiresAt,
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

// vexStatementsForExport resolves stored statements into renderer input:
// identifiers and aliases from the canonical advisory, the repository's
// product as the product, a release's version for release-scoped statements.
func (s *Server) vexStatementsForExport(ctx context.Context, org *store.Organization, repo *store.Repository, rows []dbgen.VexStatement) ([]vex.Statement, error) {
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
	product := s.repoProduct(ctx, org, repo)
	versions := map[uuid.UUID]string{}
	statements := make([]vex.Statement, 0, len(rows))
	for _, row := range rows {
		advisory, ok := advisoryByID[row.AdvisoryID]
		if !ok {
			continue
		}
		statement := vex.Statement{
			VulnerabilityID:   advisory.CanonicalID,
			Aliases:           s.advisoryAliases(ctx, advisory.ID),
			Status:            string(row.Status),
			ImpactStatement:   row.ImpactStatement,
			ActionStatement:   row.ActionStatement,
			Supplier:          row.Supplier,
			SourceDocumentURL: row.SourceDocumentUrl,
			ProductPURL:       product.PURL,
			ProductName:       product.Name,
			ProductCPE:        product.CPE,
		}
		if row.ComponentPurl.Valid {
			statement.ComponentPURL = row.ComponentPurl.String
		}
		if row.Justification.Valid {
			statement.Justification = string(row.Justification.VexJustification)
		}
		if row.ReleaseID.Valid {
			version, ok := versions[row.ReleaseID.UUID]
			if !ok {
				if release, err := s.queries.GetReleaseByID(ctx, row.ReleaseID.UUID); err == nil && release != nil {
					version = release.Version
				}
				versions[row.ReleaseID.UUID] = version
			}
			statement.ProductVersion = version
			statement.ProductCPE = cpeForVersion(product.CPE, version)
		}
		if row.VersionRange.Valid {
			statement.ProductVersion = row.VersionRange.String
		}
		statements = append(statements, statement)
	}
	return statements, nil
}

func (s *Server) advisoryAliases(ctx context.Context, advisoryID uuid.UUID) []string {
	rows, err := s.queries.Incidents().ListAliasesByAdvisory(ctx, advisoryID)
	if err != nil {
		return nil
	}
	aliases := make([]string, 0, len(rows))
	for _, row := range rows {
		aliases = append(aliases, row.Alias)
	}
	return aliases
}

func (s *Server) vexExportMeta(org *store.Organization, user *store.User, documentID string, at time.Time) vex.ExportMeta {
	meta := vex.ExportMeta{
		Author: actorDisplay(user),
		Publisher: vex.ExportPublisher{
			Category:  "vendor",
			Name:      org.DisplayName,
			Namespace: s.vexPublisherNamespace(org),
		},
		DocumentID: documentID,
		TrackingID: documentID,
		TLPLabel:   "TLP:CLEAR",
		Timestamp:  at,
		Title:      org.DisplayName + " VEX",
	}
	if strings.TrimSpace(meta.Publisher.Name) == "" {
		meta.Publisher.Name = org.Name
		meta.Title = org.Name + " VEX"
	}
	return meta
}

// applyVEXProductAxis narrows a statement to one release (which must belong to
// the repository) or to a vers range.
func (s *Server) applyVEXProductAxis(ctx context.Context, repoID uuid.UUID, releaseID, versionRange string, params *dbgen.CreateVEXStatementParams) error {
	releaseID, versionRange = strings.TrimSpace(releaseID), strings.TrimSpace(versionRange)
	if releaseID != "" && versionRange != "" {
		return errors.New("a statement names one release or one version range, not both")
	}
	if releaseID != "" {
		id, err := uuid.Parse(releaseID)
		if err != nil {
			return errors.New("invalid release_id")
		}
		release, err := s.queries.GetReleaseByID(ctx, id)
		if err != nil || release == nil || release.RepoID != repoID {
			return errors.New("release not found in this repository")
		}
		params.ReleaseID = uuid.NullUUID{UUID: id, Valid: true}
	}
	if versionRange != "" {
		if _, err := incident.ParseVers(versionRange); err != nil {
			return err
		}
		params.VersionRange = sql.NullString{String: versionRange, Valid: true}
	}
	return nil
}

// applyVEXApprovalPolicy leaves a statement unapproved when the organisation
// requires a second person; otherwise the author's statement stands approved.
func (s *Server) applyVEXApprovalPolicy(ctx context.Context, orgID uuid.UUID, params *dbgen.CreateVEXStatementParams) {
	settings, err := s.loadIncidentSettings(ctx, orgID)
	if err == nil && settings.Row.RequireVexApproval {
		params.ApprovedBy, params.ApprovedAt = uuid.NullUUID{}, sql.NullTime{}
		return
	}
	if params.CreatedBy.Valid {
		params.ApprovedBy = params.CreatedBy
		params.ApprovedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
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
	s.writeAuditLog(r, user, orgAuditID(orgID), auditEntry{
		Action:       action,
		ResourceType: "vex_statement",
		ResourceID:   statementID.String(),
		Context:      context,
	})
}

func nullTimePtr(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}
