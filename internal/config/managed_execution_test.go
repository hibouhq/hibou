package config

import (
	"strings"
	"testing"
)

func managedExecutionEnvironment(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"HIBOU_REMEDIATION_ENABLED":      "true",
		"HIBOU_WORKLOAD_IMAGE":           "registry.internal/hibou-npm@sha256:" + strings.Repeat("a", 64),
		"HIBOU_REMEDIATION_NPM_REGISTRY": "https://artifactory.internal/artifactory/api/npm/packages",
		"HIBOU_REMEDIATION_NPM_PATH":     "/usr/local/bin/npm", "HIBOU_REMEDIATION_NPM_VERSION": "10.9.4",
		"HIBOU_REMEDIATION_NODE_PATH": "/usr/local/bin/node", "HIBOU_REMEDIATION_NODE_VERSION": "v22.16.0",
		"HIBOU_REMEDIATION_TOOL_PATH": "/usr/local/bin:/usr/bin:/bin",
	} {
		t.Setenv(name, value)
	}
}

func TestManagedExecutionConfigurationAndProfileAreExplicit(t *testing.T) {
	managedExecutionEnvironment(t)
	cfg, err := ManagedExecutionFromEnv()
	if err != nil || !cfg.Enabled || !strings.HasPrefix(cfg.Profile(), "kubernetes-v1:") {
		t.Fatalf("approved profile rejected: %+v %v", cfg, err)
	}
	profile := cfg.Profile()
	t.Setenv("HIBOU_REMEDIATION_NPM_VERSION", "11.0.0")
	changed, err := ManagedExecutionFromEnv()
	if err != nil || changed.Profile() == profile {
		t.Fatal("toolchain change reused an old controller readiness profile")
	}
}

func TestManagedExecutionRejectsUnsafeOrIncompleteProfiles(t *testing.T) {
	for _, entry := range []struct{ name, value string }{
		{"HIBOU_REMEDIATION_ENABLED", "maybe"},
		{"HIBOU_WORKLOAD_IMAGE", "registry.internal/hibou:latest"},
		{"HIBOU_REMEDIATION_NPM_REGISTRY", "https://registry.npmjs.org"},
		{"HIBOU_REMEDIATION_NPM_REGISTRY", "https://user:token@mirror.internal"},
		{"HIBOU_REMEDIATION_NPM_REGISTRY", "http://mirror.internal"},
		{"HIBOU_REMEDIATION_NPM_PATH", "npm"},
		{"HIBOU_REMEDIATION_TOOL_PATH", "/usr/bin:."},
		{"HIBOU_REMEDIATION_NODE_VERSION", ""},
	} {
		t.Run(entry.name+"="+entry.value, func(t *testing.T) {
			managedExecutionEnvironment(t)
			t.Setenv(entry.name, entry.value)
			if _, err := ManagedExecutionFromEnv(); err == nil {
				t.Fatal("unsafe managed profile accepted")
			}
		})
	}
}
