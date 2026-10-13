package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestMergeOrgSettingsPatchPreservesOmittedFields(t *testing.T) {
	existing := mustRawJSON(t, map[string]any{
		"vex_auto_propagate":        true,
		"vex_reachability_analysis": true,
		"default_tlp_label":         "TLP:GREEN",
		"custom_key":                "keep",
	})
	patch := map[string]json.RawMessage{
		"default_tlp_label": mustRawJSON(t, "tlp:red"),
	}

	merged, mergedBody, err := mergeOrgSettingsPatch(existing, patch)
	if err != nil {
		t.Fatalf("mergeOrgSettingsPatch returned error: %v", err)
	}
	if !merged.VEXAutoPropagate {
		t.Fatal("expected vex_auto_propagate to be preserved")
	}
	if !merged.VEXReachabilityAnalysis {
		t.Fatal("expected vex_reachability_analysis to be preserved")
	}
	if merged.DefaultTLPLabel != "TLP:RED" {
		t.Fatalf("expected normalized tlp label, got %q", merged.DefaultTLPLabel)
	}

	var decoded map[string]any
	if err := json.Unmarshal(mergedBody, &decoded); err != nil {
		t.Fatalf("unmarshal merged settings: %v", err)
	}
	if decoded["custom_key"] != "keep" {
		t.Fatalf("expected unknown key to be preserved, got %#v", decoded)
	}
	if decoded["default_tlp_label"] != "TLP:RED" {
		t.Fatalf("expected stored tlp label to be normalized, got %#v", decoded["default_tlp_label"])
	}
}

func TestMergeOrgSettingsPatchRejectsNonObjectStoredJSON(t *testing.T) {
	_, _, err := mergeOrgSettingsPatch(json.RawMessage(`[]`), map[string]json.RawMessage{
		"default_tlp_label": mustRawJSON(t, "TLP:GREEN"),
	})
	if err == nil {
		t.Fatal("expected mergeOrgSettingsPatch to reject non-object stored json")
	}
}

func TestRedactIntegrationConfigForNonAdmin(t *testing.T) {
	integration := dbgen.Integration{
		ID:              uuid.New(),
		Name:            "alerts",
		IntegrationType: "webhook",
		Config:          mustRawJSON(t, map[string]any{"url": "https://example.com", "secret": "top-secret"}),
		Enabled:         true,
	}

	// Secret fields are write-only even for admins (second pass Q3): the
	// admin sees which keys are set, never their values.
	adminVisible := redactIntegrationConfig(integration, true)
	var adminConfig map[string]any
	if err := json.Unmarshal(adminVisible.Config, &adminConfig); err != nil {
		t.Fatalf("decode admin config: %v", err)
	}
	if adminConfig["url"] != "***" || adminConfig["secret"] != "***" {
		t.Fatalf("expected admin config secrets to be masked, got %s", adminVisible.Config)
	}
	if strings.Contains(string(adminVisible.Config), "top-secret") {
		t.Fatalf("admin config leaked the secret: %s", adminVisible.Config)
	}

	memberVisible := redactIntegrationConfig(integration, false)
	if string(memberVisible.Config) != "{}" {
		t.Fatalf("expected non-admin config to be redacted, got %s", memberVisible.Config)
	}
	if memberVisible.Name != integration.Name || memberVisible.ID != integration.ID {
		t.Fatalf("expected non-config fields to remain unchanged, got %#v", memberVisible)
	}
}

func mustRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return encoded
}
