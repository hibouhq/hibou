package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cooldown"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
)

type OrgSettings struct {
	VEXAutoPropagate        bool   `json:"vex_auto_propagate"`
	VEXReachabilityAnalysis bool   `json:"vex_reachability_analysis"`
	DefaultTLPLabel         string `json:"default_tlp_label"`
	// LoginTokens governs membership-wide device-login tokens in this org
	// (ADR-043 §4): allow, read_only (role capped at viewer) or deny.
	LoginTokens string `json:"login_tokens"`
	// Dependency policy (ADR-048 §3, ADR-045 §6): the organization's
	// defaults, which a repository's .hibou.yaml can tighten, never loosen.
	DependencyCooldownWindow      string   `json:"dependency_cooldown_window"`
	DependencyCooldownEnforcement string   `json:"dependency_cooldown_enforcement"`
	DependencyInstallConfig       string   `json:"dependency_install_config"`
	DependencyPrivateNamespaces   []string `json:"dependency_private_namespaces"`
	// TrustedDeclaredScopes lists ecosystems whose declared dev and test
	// scopes count as not shipped (default: none).
	TrustedDeclaredScopes []string `json:"trusted_declared_scopes"`
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
		if errors.Is(err, errInvalidLoginTokens) {
			api.JSONError(w, http.StatusBadRequest, "login_tokens must be one of allow, read_only, deny")
			return
		}
		if errors.Is(err, errInvalidTLPLabel) {
			api.JSONError(w, http.StatusBadRequest, "default_tlp_label must be empty or one of TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED")
			return
		}
		if errors.Is(err, errInvalidDependencyPolicy) {
			api.JSONError(w, http.StatusBadRequest, err.Error())
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
	errInvalidLoginTokens      = errors.New("invalid login tokens policy")
)

var orgSettingsPatchKeys = map[string]struct{}{
	"vex_auto_propagate":              {},
	"vex_reachability_analysis":       {},
	"default_tlp_label":               {},
	"login_tokens":                    {},
	"dependency_cooldown_window":      {},
	"dependency_cooldown_enforcement": {},
	"dependency_install_config":       {},
	"dependency_private_namespaces":   {},
	"trusted_declared_scopes":         {},
}

var errInvalidDependencyPolicy = errors.New("invalid dependency policy")

// validateDependencySettings checks the dependency policy keys (ADR-048
// §3): the same vocabulary as .hibou.yaml.
func validateDependencySettings(settings OrgSettings) error {
	if _, _, _, err := cooldown.ParseWindow(settings.DependencyCooldownWindow); err != nil {
		return fmt.Errorf("%w: dependency_cooldown_window: %w", errInvalidDependencyPolicy, err)
	}
	switch strings.ToLower(strings.TrimSpace(settings.DependencyCooldownEnforcement)) {
	case "", "inherit", "advisory", "blocking":
	default:
		return fmt.Errorf("%w: dependency_cooldown_enforcement must be inherit, advisory or blocking", errInvalidDependencyPolicy)
	}
	switch strings.ToLower(strings.TrimSpace(settings.DependencyInstallConfig)) {
	case "", "require", "warn", "off":
	default:
		return fmt.Errorf("%w: dependency_install_config must be require, warn or off", errInvalidDependencyPolicy)
	}
	for _, pattern := range settings.DependencyPrivateNamespaces {
		if !strings.HasPrefix(strings.TrimSpace(pattern), "pkg:") {
			return fmt.Errorf("%w: dependency_private_namespaces: %q must be a purl pattern", errInvalidDependencyPolicy, pattern)
		}
	}
	return nil
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
	if !isValidLoginTokens(merged.LoginTokens) {
		return OrgSettings{}, nil, errInvalidLoginTokens
	}
	if err := validateDependencySettings(merged); err != nil {
		return OrgSettings{}, nil, err
	}
	if _, ok := patch["login_tokens"]; ok {
		normalized, err := json.Marshal(merged.LoginTokens)
		if err != nil {
			return OrgSettings{}, nil, err
		}
		existing["login_tokens"] = normalized
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
	settings.LoginTokens = normalizeLoginTokens(settings.LoginTokens)
	return settings, nil
}

// normalizeLoginTokens maps an unset policy to the default, allow. An
// unrecognised stored value is kept so validation can reject it on write.
func normalizeLoginTokens(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return rbac.LoginTokensAllow
	}
	return value
}

func isValidLoginTokens(value string) bool {
	switch value {
	case rbac.LoginTokensAllow, rbac.LoginTokensReadOnly, rbac.LoginTokensDeny:
		return true
	default:
		return false
	}
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
