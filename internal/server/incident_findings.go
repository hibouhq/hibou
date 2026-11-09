package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cvss"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Finding-side pieces of ADR-053: the secret revocation checklist and
// re-check (§4, amending ADR-023), and first-party vulnerability records
// (§4a).

// secretChecklist is the structured attestation: revoked where and by whom,
// rotated (or why not), exposure assessed, and whether the credential belongs
// to someone else.
type secretChecklist struct {
	Revoked       bool   `json:"revoked"`
	RevokedWhere  string `json:"revoked_where"`
	RevokedBy     string `json:"revoked_by"`
	Reference     string `json:"reference"`
	Rotation      string `json:"rotation"`
	RotationNote  string `json:"rotation_note"`
	Exposure      string `json:"exposure"`
	ExposureNote  string `json:"exposure_note"`
	OwnerExternal bool   `json:"owner_external"`
}

func (c secretChecklist) validate() string {
	if c.Revoked && strings.TrimSpace(c.RevokedWhere) == "" {
		return "say where the credential was revoked"
	}
	switch c.Rotation {
	case "", "rotated":
	case "not_needed":
		if strings.TrimSpace(c.RotationNote) == "" {
			return "say why no new credential is needed"
		}
	default:
		return `rotation must be "rotated" or "not_needed"`
	}
	switch c.Exposure {
	case "", "assessed":
	default:
		return `exposure must be "assessed"`
	}
	if !c.Revoked && c.Rotation == "" && c.Exposure == "" {
		return "the checklist records at least one step"
	}
	return ""
}

func (s *Server) loadSecretFinding(w http.ResponseWriter, r *http.Request, write bool) (*store.Organization, *store.Repository, *store.User, *store.Vulnerability, bool) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return nil, nil, nil, nil, false
	}
	access := apitoken.AccessRead
	if write {
		access = apitoken.AccessWrite
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, access, org.Slug, repo.Slug) {
		return nil, nil, nil, nil, false
	}
	vulnID, err := uuid.Parse(chi.URLParam(r, "vulnID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid vulnerability id")
		return nil, nil, nil, nil, false
	}
	finding, err := s.queries.GetVulnerabilityByID(r.Context(), vulnID)
	if err != nil || finding == nil || !s.vulnerabilityBelongsToRepo(r, repo, finding) {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return nil, nil, nil, nil, false
	}
	if finding.Type != "secret" {
		api.JSONError(w, http.StatusUnprocessableEntity, "this applies to secret findings only")
		return nil, nil, nil, nil, false
	}
	return org, repo, user, finding, true
}

// recordSecretChecklist stores the checklist, resolves the finding when the
// credential is revoked, and reconciles the finding's incidents.
func (s *Server) recordSecretChecklist(r *http.Request, org *store.Organization, repo *store.Repository, user *store.User, finding *store.Vulnerability, checklist secretChecklist, note string) (dbgen.SecretAttestation, error) {
	attestedBy := uuid.NullUUID{}
	if user != nil {
		attestedBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	row, err := s.queries.Incidents().CreateSecretAttestation(r.Context(), dbgen.CreateSecretAttestationParams{
		RepoID: repo.ID, Fingerprint: finding.Fingerprint, Revoked: checklist.Revoked,
		RevokedWhere: strings.TrimSpace(checklist.RevokedWhere), RevokedBy: strings.TrimSpace(checklist.RevokedBy),
		Reference: strings.TrimSpace(checklist.Reference), Rotation: checklist.Rotation, RotationNote: strings.TrimSpace(checklist.RotationNote),
		Exposure: checklist.Exposure, ExposureNote: strings.TrimSpace(checklist.ExposureNote), OwnerExternal: checklist.OwnerExternal,
		Note: strings.TrimSpace(note), AttestedBy: attestedBy,
	})
	if err != nil {
		return row, err
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionSecretAttested, map[string]any{
		"finding_id": finding.ID.String(), "fingerprint": finding.Fingerprint, "revoked": checklist.Revoked,
		"revoked_where": checklist.RevokedWhere, "rotation": checklist.Rotation, "exposure": checklist.Exposure, "reference": checklist.Reference,
	})
	s.reconcileFindingIncidents(r, org.ID, repo.ID, finding.Fingerprint)
	return row, nil
}

func (s *Server) reconcileFindingIncidents(r *http.Request, orgID, repoID uuid.UUID, fingerprint string) {
	rows, err := s.queries.Incidents().ListOpenIncidentsBySubject(r.Context(), dbgen.ListOpenIncidentsBySubjectParams{OrgID: orgID, SubjectType: incident.SubjectFinding, SubjectIds: []string{fingerprint}})
	if err != nil {
		return
	}
	for _, row := range rows {
		if row.RepoID.Valid && row.RepoID.UUID == repoID {
			_, _ = s.reconcileIncident(r.Context(), row.ID)
		}
	}
}

// handleListSecretAttestations returns the checklist history of a secret.
func (s *Server) handleListSecretAttestations(w http.ResponseWriter, r *http.Request) {
	_, repo, _, finding, ok := s.loadSecretFinding(w, r, false)
	if !ok {
		return
	}
	rows, err := s.queries.Incidents().ListSecretAttestations(r.Context(), dbgen.ListSecretAttestationsParams{RepoID: repo.ID, Fingerprint: finding.Fingerprint})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list attestations")
		return
	}
	api.JSON(w, http.StatusOK, rows)
}

// handleRecheckSecret asks the validators again (§4 "proof beats
// attestation"): hibou keeps hashes, never secrets, so the check runs as a
// secret scan of the branch, whose validating scanners record the verdict on
// the finding. A confirmed-dead credential then resolves.
func (s *Server) handleRecheckSecret(w http.ResponseWriter, r *http.Request) {
	org, repo, user, finding, ok := s.loadSecretFinding(w, r, true)
	if !ok {
		return
	}
	if !s.cfg.SecretScan.Enabled {
		api.JSONError(w, http.StatusConflict, "secret scanning is not enabled on this instance")
		return
	}
	refName := repo.DefaultBranch
	if snapshot, err := s.queries.GetSnapshotByID(r.Context(), finding.SnapshotID); err == nil && snapshot != nil {
		if ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID); err == nil && ref != nil && ref.RefType == store.RefTypeBranch {
			refName = ref.Name
		}
	}
	job, err := s.queries.EnqueueSecretScanJob(r.Context(), store.EnqueueSecretScanJobParams{RepoID: repo.ID, RefName: refName, Mode: store.SecretScanModeFull})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to enqueue the re-check")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionScanTrigger, map[string]any{
		"job_id": job.ID.String(), "ref": refName, "mode": job.Mode, "reason": "secret re-check", "finding_id": finding.ID.String(),
	})
	api.JSON(w, http.StatusAccepted, map[string]any{"job_id": job.ID, "ref": refName, "status": job.Status})
}

type firstPartyAdvisoryRequest struct {
	Identifier    string   `json:"identifier"`
	Aliases       []string `json:"aliases,omitempty"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Severity      string   `json:"severity"`
	CVSSVector    string   `json:"cvss_vector,omitempty"`
	AffectedRange string   `json:"affected_range"`
	PromotedFrom  string   `json:"promoted_from,omitempty"`
}

// handleCreateFirstPartyAdvisory records a vulnerability in the product's own
// code (ADR-053 §4a): a canonical advisory under the manufacturer's identifier
// (a CVE, or a vendor identifier until one exists), with the affected release
// range. From there statements, incidents and notices treat it like any
// advisory; a CVE assigned later becomes an alias of the same row.
func (s *Server) handleCreateFirstPartyAdvisory(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok || !s.requireReleaseManager(r, w, org.ID) {
		return
	}
	var input firstPartyAdvisoryRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	identifier := strings.TrimSpace(input.Identifier)
	if identifier == "" || strings.ContainsAny(identifier, " \t\n/") {
		api.JSONError(w, http.StatusBadRequest, "identifier is a CVE or a vendor identifier such as VENDOR-2026-001")
		return
	}
	if strings.TrimSpace(input.Title) == "" {
		api.JSONError(w, http.StatusBadRequest, "title is required")
		return
	}
	if _, err := incident.ParseVers(input.AffectedRange); err != nil {
		api.JSONError(w, http.StatusBadRequest, "affected_range: "+err.Error())
		return
	}
	severity := dbgen.SeverityLevel(strings.ToLower(strings.TrimSpace(input.Severity)))
	switch severity {
	case dbgen.SeverityLevelCritical, dbgen.SeverityLevelHigh, dbgen.SeverityLevelMedium, dbgen.SeverityLevelLow, dbgen.SeverityLevelInfo:
	default:
		api.JSONError(w, http.StatusBadRequest, "severity must be critical, high, medium, low or info")
		return
	}
	promotedFrom := sql.NullString{}
	if raw := strings.TrimSpace(input.PromotedFrom); raw != "" {
		findingID, err := uuid.Parse(raw)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "promoted_from is a finding id")
			return
		}
		finding, err := s.queries.GetVulnerabilityByID(r.Context(), findingID)
		if err != nil || finding == nil || !s.vulnerabilityBelongsToRepo(r, repo, finding) {
			api.JSONError(w, http.StatusNotFound, "promoted finding not found in this repository")
			return
		}
		promotedFrom = sql.NullString{String: finding.Fingerprint, Valid: true}
	}
	ctx := r.Context()
	advisory, err := s.queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{CanonicalID: identifier, Title: strings.TrimSpace(input.Title), Description: strings.TrimSpace(input.Description)})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store the advisory")
		return
	}
	rating := dbgen.SetAdvisoryRatingParams{AdvisoryID: advisory.ID, Severity: severity, RatedBy: "first-party"}
	if raw := strings.TrimSpace(input.CVSSVector); raw != "" {
		vector, score, err := cvss.Score(raw)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "cvss_vector: "+err.Error())
			return
		}
		rating.CvssVector = raw
		rating.CvssVersion = dbgen.NullCvssVersion{CvssVersion: dbgen.CvssVersion(vector.Version), Valid: true}
		if score != nil {
			rating.CvssScore = sql.NullString{String: strconv.FormatFloat(*score, 'f', 1, 64), Valid: true}
		}
	}
	if _, err := s.queries.SetAdvisoryRating(ctx, rating); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to rate the advisory")
		return
	}
	for _, alias := range input.Aliases {
		if alias = strings.TrimSpace(alias); alias != "" && alias != identifier {
			_ = s.queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisory.ID, Alias: alias})
		}
	}
	product := s.repoProduct(ctx, org, repo)
	user := UserFromContext(ctx)
	createdBy := uuid.NullUUID{}
	if user != nil {
		createdBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	row, err := s.queries.CreateFirstPartyAdvisory(ctx, dbgen.CreateFirstPartyAdvisoryParams{
		OrgID: org.ID, RepoID: repo.ID, AdvisoryID: advisory.ID, ProductPurl: product.PURL,
		ProductCpe: nullStringValue(product.CPE), AffectedRange: strings.TrimSpace(input.AffectedRange),
		PromotedFrom: promotedFrom, CreatedBy: createdBy,
	})
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusConflict, "this repository already records that vulnerability")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to record the first-party advisory")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFirstPartyCreate, map[string]any{
		"advisory_id": advisory.ID.String(), "identifier": identifier, "affected_range": row.AffectedRange, "promoted_from": promotedFrom.String,
	})
	api.JSON(w, http.StatusCreated, row)
}

func (s *Server) handleListFirstPartyAdvisories(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	rows, err := s.queries.ListFirstPartyAdvisoriesByRepo(r.Context(), repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list first-party advisories")
		return
	}
	api.JSON(w, http.StatusOK, rows)
}

func decodeChecklist(raw json.RawMessage) (secretChecklist, bool) {
	var checklist secretChecklist
	if len(raw) == 0 || string(raw) == "null" {
		return checklist, false
	}
	return checklist, json.Unmarshal(raw, &checklist) == nil
}
