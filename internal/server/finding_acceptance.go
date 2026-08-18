package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
)

type findingAcceptanceRequest struct {
	// Status: "accepted" or "open" — the only transition (ADR-023).
	Status string `json:"status"`
	// ReasonKind is required on accept: "risk_accepted" | "false_positive".
	ReasonKind string   `json:"reason_kind"`
	Reason     string   `json:"reason"`
	Labels     []string `json:"labels,omitempty"`
	// VEXJustification: only for false-positive dependency findings — the
	// standard CISA/OpenVEX vocabulary for the generated not_affected statement.
	VEXJustification string     `json:"vex_justification,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// validateAcceptanceDecision enforces the ADR-023 rules shared by the single
// and batch endpoints. componentBacked toggles VEX vocabulary legality.
func validateAcceptanceDecision(reasonKind, reason, vexJustification string, expiresAt *time.Time, componentBacked bool) (string, error) {
	switch reasonKind {
	case "risk_accepted", "false_positive":
	default:
		return "", errAcceptance(`reason_kind must be "risk_accepted" or "false_positive"`)
	}
	if strings.TrimSpace(reason) == "" && vexJustification == "" {
		return "", errAcceptance("a reason is required to accept a finding")
	}
	if expiresAt != nil && expiresAt.Before(time.Now()) {
		return "", errAcceptance("expires_at must be in the future")
	}
	if vexJustification != "" {
		if reasonKind != "false_positive" {
			return "", errAcceptance("vex_justification is only valid with reason_kind=false_positive (the VEX standard forbids justifications on affected statements)")
		}
		if !componentBacked {
			return "", errAcceptance("vex_justification only applies to component-backed (dependency) findings")
		}
		switch vexJustification {
		case "component_not_present", "vulnerable_code_not_present",
			"vulnerable_code_not_in_execute_path",
			"vulnerable_code_cannot_be_controlled_by_adversary",
			"inline_mitigations_already_exist":
		default:
			return "", errAcceptance("vex_justification must be one of the CISA/OpenVEX status justifications")
		}
	}
	return reasonKind, nil
}

type acceptanceValidationError struct{ msg string }

func (e acceptanceValidationError) Error() string { return e.msg }

func errAcceptance(msg string) error { return acceptanceValidationError{msg: msg} }

// componentBackedFindingType reports whether VEX vocabulary applies: VEX
// describes exploitability of components in a product, nothing else.
func componentBackedFindingType(findingType string) bool {
	return findingType == "dependency" || findingType == "container"
}

// @Summary      Accept or reopen a finding
// @Description  Accepts a finding (with a required reason) or reopens it. Decisions are fingerprint-scoped so they survive new snapshots, and the PR gate re-evaluates immediately.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        vulnID    path  string  true  "Vulnerability ID"
// @Param        payload   body  server.findingAcceptanceRequest  true  "Acceptance"
// @Success      200  {object}  api.Response{data=store.FindingAcceptance}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/vulnerabilities/{vulnID}/acceptance [put]
func (s *Server) handleSetFindingAcceptance(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}

	vulnID, err := uuid.Parse(chi.URLParam(r, "vulnID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid vulnerability id")
		return
	}
	vulnerability, err := s.queries.GetVulnerabilityByID(r.Context(), vulnID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return
	}
	if vulnerability == nil || !s.vulnerabilityBelongsToRepo(r, repo, vulnerability) {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}
	fingerprint := strings.TrimSpace(vulnerability.Fingerprint)
	if fingerprint == "" {
		api.JSONError(w, http.StatusUnprocessableEntity, "finding has no fingerprint to key an acceptance on")
		return
	}

	var input findingAcceptanceRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	status := strings.ToLower(strings.TrimSpace(input.Status))

	switch status {
	case "open":
		if _, err := s.queries.DeleteFindingAcceptance(r.Context(), repo.ID, fingerprint); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to reopen finding")
			return
		}
		s.writeAcceptanceAuditLog(r, user, org.ID, repo.ID, acceptanceAudit{Fingerprint: fingerprint, Status: "open"})
		s.publishGateRecompute(r.Context(), repo.ID)
		api.JSON(w, http.StatusOK, map[string]string{"status": "open"})
		return
	case "accepted":
	default:
		api.JSONError(w, http.StatusBadRequest, `status must be "accepted" or "open"`)
		return
	}

	reasonKind, err := validateAcceptanceDecision(input.ReasonKind, input.Reason, input.VEXJustification, input.ExpiresAt, componentBackedFindingType(vulnerability.Type))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var acceptedBy *uuid.UUID
	if user != nil {
		acceptedBy = &user.ID
	}
	var vexJustification *string
	if input.VEXJustification != "" {
		vexJustification = &input.VEXJustification
	}
	acceptance, err := s.queries.UpsertFindingAcceptance(r.Context(), store.AcceptFindingInput{
		RepoID:           repo.ID,
		Fingerprint:      fingerprint,
		ReasonKind:       reasonKind,
		Reason:           strings.TrimSpace(input.Reason),
		Labels:           normalizeAcceptanceLabels(input.Labels),
		VEXJustification: vexJustification,
		AcceptedBy:       acceptedBy,
		ExpiresAt:        input.ExpiresAt,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store acceptance")
		return
	}

	s.writeAcceptanceAuditLog(r, user, org.ID, repo.ID, acceptanceAudit{
		Fingerprint:      fingerprint,
		Status:           reasonKind,
		Reason:           strings.TrimSpace(input.Reason),
		Labels:           acceptance.Labels,
		VEXJustification: input.VEXJustification,
		ExpiresAt:        input.ExpiresAt,
	})
	// The gate must reflect the decision immediately, without a CI re-run.
	s.publishGateRecompute(r.Context(), repo.ID)
	api.JSON(w, http.StatusOK, acceptance)
}

// normalizeAcceptanceLabels trims, lowercases, dedupes, and bounds labels —
// they are for filtering, so canonical form matters more than fidelity.
func normalizeAcceptanceLabels(labels []string) []string {
	const maxLabels = 16
	seen := make(map[string]struct{}, len(labels))
	out := make([]string, 0, len(labels))
	for _, label := range labels {
		normalized := strings.ToLower(strings.TrimSpace(label))
		if normalized == "" || len(normalized) > 64 {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
		if len(out) == maxLabels {
			break
		}
	}
	return out
}

// maxBatchAcceptance bounds one request so a runaway "select all" cannot write
// unbounded rows in a single transaction.
const maxBatchAcceptance = 500

type batchAcceptanceRequest struct {
	// Fingerprints identify the findings; decisions are fingerprint-keyed so they
	// survive snapshot churn, same as the single-finding endpoint.
	Fingerprints []string `json:"fingerprints"`
	// Status: "accepted" | "open"; ReasonKind required on accept (ADR-023).
	Status     string     `json:"status"`
	ReasonKind string     `json:"reason_kind"`
	Reason     string     `json:"reason"`
	Labels     []string   `json:"labels,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type batchAcceptanceResponse struct {
	Status  string `json:"status"`
	Applied int    `json:"applied"`
	// Skipped counts fingerprints that do not belong to this repository, so a
	// partial apply is never silent.
	Skipped int `json:"skipped"`
}

// @Summary      Triage many findings at once
// @Description  Applies one decision and one reason to many findings by fingerprint. Fingerprints outside the repository are skipped and reported. The PR gate recomputes once at the end.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        payload   body  server.batchAcceptanceRequest  true  "Batch decision"
// @Success      200  {object}  api.Response{data=server.batchAcceptanceResponse}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/vulnerabilities/acceptance [put]
func (s *Server) handleBatchFindingAcceptance(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}

	var input batchAcceptanceRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	status := strings.ToLower(strings.TrimSpace(input.Status))
	if status != "open" && status != "accepted" {
		api.JSONError(w, http.StatusBadRequest, `status must be "accepted" or "open"`)
		return
	}
	reason := strings.TrimSpace(input.Reason)
	reasonKind := input.ReasonKind
	if status == "accepted" {
		// Batch decisions never carry VEX justifications: those are
		// per-finding statements about specific components.
		var err error
		reasonKind, err = validateAcceptanceDecision(input.ReasonKind, reason, "", input.ExpiresAt, false)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	requested := dedupeFingerprints(input.Fingerprints)
	if len(requested) == 0 {
		api.JSONError(w, http.StatusBadRequest, "at least one fingerprint is required")
		return
	}
	if len(requested) > maxBatchAcceptance {
		api.JSONError(w, http.StatusBadRequest, fmt.Sprintf("too many findings in one request (%d, max %d)", len(requested), maxBatchAcceptance))
		return
	}

	// Only fingerprints that actually belong to this repo may be written.
	owned, err := s.queries.ListRepoFingerprints(r.Context(), repo.ID, requested)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to validate findings")
		return
	}
	if len(owned) == 0 {
		api.JSONError(w, http.StatusNotFound, "none of the given findings belong to this repository")
		return
	}

	var acceptedBy *uuid.UUID
	if user != nil {
		acceptedBy = &user.ID
	}
	applied := 0
	for _, fingerprint := range owned {
		if status == "open" {
			if _, err := s.queries.DeleteFindingAcceptance(r.Context(), repo.ID, fingerprint); err != nil {
				api.JSONError(w, http.StatusInternalServerError, "failed to reopen findings")
				return
			}
		} else if _, err := s.queries.UpsertFindingAcceptance(r.Context(), store.AcceptFindingInput{
			RepoID:      repo.ID,
			Fingerprint: fingerprint,
			ReasonKind:  reasonKind,
			Reason:      reason,
			Labels:      normalizeAcceptanceLabels(input.Labels),
			AcceptedBy:  acceptedBy,
			ExpiresAt:   input.ExpiresAt,
		}); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to store acceptances")
			return
		}
		applied++
		// One audit entry per finding: a batch decision must stay individually
		// auditable, otherwise the trail cannot answer "who suppressed this one".
		auditEntry := acceptanceAudit{Fingerprint: fingerprint, Status: status, Reason: reason}
		if status == "accepted" {
			auditEntry.Status = reasonKind
			auditEntry.Labels = normalizeAcceptanceLabels(input.Labels)
			auditEntry.ExpiresAt = input.ExpiresAt
		}
		s.writeAcceptanceAuditLog(r, user, org.ID, repo.ID, auditEntry)
	}

	// One recompute for the whole batch, not one per finding.
	s.publishGateRecompute(r.Context(), repo.ID)

	api.JSON(w, http.StatusOK, batchAcceptanceResponse{
		Status:  status,
		Applied: applied,
		Skipped: len(requested) - applied,
	})
}

func dedupeFingerprints(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

// @Summary      List active finding acceptances
// @Tags         vulnerabilities
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=[]store.FindingAcceptance}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/finding-acceptances [get]
func (s *Server) handleListFindingAcceptances(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	acceptances, err := s.queries.ListActiveFindingAcceptancesByRepo(r.Context(), repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list acceptances")
		return
	}
	if acceptances == nil {
		acceptances = []store.FindingAcceptance{}
	}
	api.JSON(w, http.StatusOK, acceptances)
}

// vulnerabilityBelongsToRepo walks snapshot → ref → repo to stop cross-repo
// acceptance writes.
func (s *Server) vulnerabilityBelongsToRepo(r *http.Request, repo *store.Repository, vulnerability *store.Vulnerability) bool {
	snapshot, err := s.queries.GetSnapshotByID(r.Context(), vulnerability.SnapshotID)
	if err != nil || snapshot == nil {
		return false
	}
	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil || ref == nil {
		return false
	}
	return ref.RepoID == repo.ID
}

// acceptanceAudit is the decision as recorded, not merely that one was taken:
// the finding-history timeline reads these fields back, and "who suppressed
// this, why, with what expiry" is unanswerable if the write drops them.
type acceptanceAudit struct {
	Fingerprint      string
	Status           string
	Reason           string
	Labels           []string
	VEXJustification string
	ExpiresAt        *time.Time
}

func (s *Server) writeAcceptanceAuditLog(r *http.Request, user *store.User, orgID, repoID uuid.UUID, entry acceptanceAudit) {
	context := map[string]any{
		"fingerprint": entry.Fingerprint,
		"status":      entry.Status,
		"reason":      entry.Reason,
	}
	if len(entry.Labels) > 0 {
		context["labels"] = entry.Labels
	}
	if entry.VEXJustification != "" {
		context["vex_justification"] = entry.VEXJustification
	}
	if entry.ExpiresAt != nil {
		context["expires_at"] = entry.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.writeRepositoryAuditLog(r, user, orgID, repoID, audit.ActionFindingAcceptance, context)
}

type secretRevocationRequest struct {
	Comment string `json:"comment"`
}

// @Summary      Attest secret revocation
// @Description  Marks a leaked-secret finding resolved after a human verified the credential was revoked/rotated. Secrets never auto-resolve from scan absence (ADR-023) — this attestation is the only resolution path.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        vulnID    path  string  true  "Vulnerability ID"
// @Param        payload   body  server.secretRevocationRequest  true  "Attestation"
// @Success      200  {object}  api.Response{data=store.Vulnerability}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      422  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/vulnerabilities/{vulnID}/revocation [post]
func (s *Server) handleAttestSecretRevocation(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}

	vulnID, err := uuid.Parse(chi.URLParam(r, "vulnID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid vulnerability id")
		return
	}
	vulnerability, err := s.queries.GetVulnerabilityByID(r.Context(), vulnID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return
	}
	if vulnerability == nil || !s.vulnerabilityBelongsToRepo(r, repo, vulnerability) {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}
	if vulnerability.Type != "secret" {
		api.JSONError(w, http.StatusUnprocessableEntity, "revocation attestation only applies to secret findings; other types resolve when scans stop reporting them")
		return
	}

	var input secretRevocationRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	comment := "secret revoked & rotated (attested)"
	if strings.TrimSpace(input.Comment) != "" {
		comment += ": " + strings.TrimSpace(input.Comment)
	}
	var attestedBy *uuid.UUID
	if user != nil {
		attestedBy = &user.ID
	}
	updated, err := s.queries.UpdateVulnerabilityStatus(r.Context(), vulnID, "resolved", &comment, attestedBy)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record revocation")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionSecretRevoked, map[string]any{
		"finding_id":  vulnID.String(),
		"fingerprint": vulnerability.Fingerprint,
		"comment":     strings.TrimSpace(input.Comment),
	})
	s.publishGateRecompute(r.Context(), repo.ID)
	api.JSON(w, http.StatusOK, updated)
}
