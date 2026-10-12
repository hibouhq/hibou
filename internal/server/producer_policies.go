package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
)

type producerPoliciesResponse struct {
	// Policies are the org's explicit choices; a producer without one uses
	// the default (coverage, or explicit for agent:* producers).
	Policies         []store.ProducerPolicy `json:"policies"`
	DefaultThreshold int                    `json:"default_threshold"`
}

type setProducerPolicyRequest struct {
	Producer  string `json:"producer"`
	Policy    string `json:"policy"`
	Threshold int    `json:"threshold"`
}

// @Summary      Producer resolution policies
// @Description  How each producer's absent findings are resolved (ADR-034 §5): "coverage" (re-checked and the code changed), "consecutive-absence" (N covered scans without it) or "explicit" (only a decision). Producers without a row use the default.
// @Tags         findings
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  api.Response{data=server.producerPoliciesResponse}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/producer-policies [get]
func (s *Server) handleListProducerPolicies(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	policies, err := s.queries.ListProducerPolicies(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load producer policies")
		return
	}
	api.JSON(w, http.StatusOK, producerPoliciesResponse{Policies: policies, DefaultThreshold: presence.DefaultAbsenceThreshold})
}

// @Summary      Set a producer's resolution policy
// @Description  Org admins only. threshold is N for consecutive-absence and the number of unchanged covered scans after which an unconfirmed finding is no longer reported (1–100, default 3).
// @Tags         findings
// @Accept       json
// @Produce      json
// @Param        provider  path  string                           true  "Forge provider"
// @Param        slug      path  string                           true  "Organization slug"
// @Param        payload   body  server.setProducerPolicyRequest  true  "Policy"
// @Success      200  {object}  api.Response{data=store.ProducerPolicy}
// @Failure      400  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/producer-policies [put]
func (s *Server) handleSetProducerPolicy(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	var request setProducerPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Producer = strings.ToLower(strings.TrimSpace(request.Producer))
	if request.Producer == "" || len(request.Producer) > 200 {
		api.JSONError(w, http.StatusBadRequest, "producer is required (at most 200 characters)")
		return
	}
	switch request.Policy {
	case presence.PolicyCoverage, presence.PolicyConsecutiveAbsence, presence.PolicyExplicit, presence.PolicyRetired:
	default:
		api.JSONError(w, http.StatusBadRequest, "policy must be coverage, consecutive-absence, explicit or retired")
		return
	}
	if request.Threshold == 0 {
		request.Threshold = presence.DefaultAbsenceThreshold
	}
	if request.Threshold < 1 || request.Threshold > 100 {
		api.JSONError(w, http.StatusBadRequest, "threshold must be between 1 and 100")
		return
	}
	var actor *uuid.UUID
	if user != nil {
		id := user.ID
		actor = &id
	}
	saved, err := s.queries.UpsertProducerPolicy(r.Context(), org.ID, store.ProducerPolicy{
		Producer: request.Producer, Policy: request.Policy, Threshold: request.Threshold, UpdatedBy: actor,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save producer policy")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
		Action:       audit.ActionSettingUpdate,
		ResourceType: "producer_policy",
		ResourceID:   request.Producer,
		Context:      map[string]any{"policy": request.Policy, "threshold": request.Threshold},
	})
	api.JSON(w, http.StatusOK, saved)
}

// @Summary      Reset a producer's resolution policy to the default
// @Tags         findings
// @Param        provider  path   string  true  "Forge provider"
// @Param        slug      path   string  true  "Organization slug"
// @Param        producer  query  string  true  "Producer name"
// @Success      204
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/producer-policies [delete]
func (s *Server) handleDeleteProducerPolicy(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	producer := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("producer")))
	deleted, err := s.queries.DeleteProducerPolicy(r.Context(), org.ID, producer)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to reset producer policy")
		return
	}
	if !deleted {
		api.JSONError(w, http.StatusNotFound, "no policy set for this producer")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
		Action:       audit.ActionSettingUpdate,
		ResourceType: "producer_policy",
		ResourceID:   producer,
		Context:      map[string]any{"policy": "default"},
	})
	w.WriteHeader(http.StatusNoContent)
}
