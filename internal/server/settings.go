package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
)

type OrgSettings struct {
	VEXAutoPropagate        bool   `json:"vex_auto_propagate"`
	VEXReachabilityAnalysis bool   `json:"vex_reachability_analysis"`
	DefaultTLPLabel         string `json:"default_tlp_label"`
}

func (s *Server) handleGetOrgSettings(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	settings, err := parseOrgSettings(org.Settings)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to decode organization settings")
		return
	}
	api.JSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateOrgSettings(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	user := UserFromContext(r.Context())
	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	role, err := s.principalOrgRole(r, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if role != "admin" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	previous, err := parseOrgSettings(org.Settings)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to decode organization settings")
		return
	}

	var patch map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input, settingsBody, err := mergeOrgSettingsPatch(org.Settings, patch)
	if err != nil {
		if errors.Is(err, errInvalidOrgSettingsPatch) {
			api.JSONError(w, http.StatusBadRequest, "invalid settings payload")
			return
		}
		if errors.Is(err, errInvalidTLPLabel) {
			api.JSONError(w, http.StatusBadRequest, "default_tlp_label must be empty or one of TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to decode organization settings")
		return
	}
	updated, err := s.queries.UpdateOrganizationSettings(r.Context(), org.ID, settingsBody)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update organization settings")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	s.writeSettingsAuditLog(r, user, org.ID, previous, input)
	api.JSON(w, http.StatusOK, input)
}

var (
	errInvalidOrgSettingsPatch = errors.New("invalid settings patch")
	errInvalidTLPLabel         = errors.New("invalid tlp label")
)

var orgSettingsPatchKeys = map[string]struct{}{
	"vex_auto_propagate":        {},
	"vex_reachability_analysis": {},
	"default_tlp_label":         {},
}

func mergeOrgSettingsPatch(existingRaw json.RawMessage, patch map[string]json.RawMessage) (OrgSettings, json.RawMessage, error) {
	existing, err := decodeJSONObject(defaultRawJSON(existingRaw, "{}"))
	if err != nil {
		return OrgSettings{}, nil, err
	}
	hasDefaultTLPLabel := hasJSONObjectKey(existing, "default_tlp_label")
	for key, value := range patch {
		if _, ok := orgSettingsPatchKeys[key]; !ok {
			continue
		}
		existing[key] = value
	}
	mergedBody, err := json.Marshal(existing)
	if err != nil {
		return OrgSettings{}, nil, err
	}
	merged, err := parseOrgSettings(mergedBody)
	if err != nil {
		return OrgSettings{}, nil, errInvalidOrgSettingsPatch
	}
	if !isValidTLPLabel(merged.DefaultTLPLabel) {
		return OrgSettings{}, nil, errInvalidTLPLabel
	}
	if _, ok := patch["default_tlp_label"]; ok || hasDefaultTLPLabel {
		normalized, err := json.Marshal(merged.DefaultTLPLabel)
		if err != nil {
			return OrgSettings{}, nil, err
		}
		existing["default_tlp_label"] = normalized
	}
	settingsBody, err := json.Marshal(existing)
	if err != nil {
		return OrgSettings{}, nil, err
	}
	return merged, settingsBody, nil
}

func decodeJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return map[string]json.RawMessage{}, nil
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return nil, err
	}
	if decoded == nil {
		return map[string]json.RawMessage{}, nil
	}
	return decoded, nil
}

func hasJSONObjectKey(values map[string]json.RawMessage, key string) bool {
	_, ok := values[key]
	return ok
}

func parseOrgSettings(raw json.RawMessage) (OrgSettings, error) {
	var settings OrgSettings
	if err := json.Unmarshal(defaultRawJSON(raw, "{}"), &settings); err != nil {
		return OrgSettings{}, err
	}
	settings.DefaultTLPLabel = normalizeTLPLabel(settings.DefaultTLPLabel)
	return settings, nil
}

func normalizeTLPLabel(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func isValidTLPLabel(value string) bool {
	switch value {
	case "", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED":
		return true
	default:
		return false
	}
}

func (s *Server) writeSettingsAuditLog(r *http.Request, user *store.User, orgID uuid.UUID, previous, current OrgSettings) {
	s.writeAuditLog(r, user, orgAuditID(orgID), auditEntry{
		Action:       audit.ActionSettingUpdate,
		ResourceType: "organization",
		ResourceID:   orgID.String(),
		Context: map[string]any{
			"old_settings": previous,
			"new_settings": current,
		},
	})
}
