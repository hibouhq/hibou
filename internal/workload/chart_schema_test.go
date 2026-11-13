package workload

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func lintChart(t *testing.T, values map[string]any) ([]byte, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm unavailable")
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helm, "lint", filepath.Join("..", "..", "chart", "hibou"), "--namespace", "application", "--kube-version", "1.36.0", "--values", "-")
	cmd.Stdin = bytes.NewReader(data)
	return cmd.CombinedOutput()
}
func setChartValue(values map[string]any, path []string, value any) {
	for _, key := range path[:len(path)-1] {
		next, ok := values[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			values[key] = next
		}
		values = next
	}
	values[path[len(path)-1]] = value
}
func TestChartSchemaRejectsUnsafeValues(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		value      any
		schema     bool
	}{
		{"same-namespace", "workload.namespace.name", "application", false},
		{"unqualified-runtime", "workload.runtimeValidated", false, true},
		{"missing-runtime", "workload.runtimeClassName", "", true},
		{"missing-ca", "workload.caBundle", "", true},
		{"malformed-ca", "workload.caBundle", "-----BEGIN CERTIFICATE-----without-end", true},
		{"tagged-image", "workload.image", "mirror/tool:latest", true},
		{"short-digest", "workload.image", "mirror/tool@sha256:" + strings.Repeat("a", 63), true},
		{"wrong-digest-algorithm", "workload.image", "mirror/tool@sha512:" + strings.Repeat("a", 64), true},
		{"uppercase-digest", "workload.image", "mirror/tool@sha256:" + strings.Repeat("A", 64), true},
		{"string-enable", "workload.enabled", "true", true},
		{"namespace-create-type", "workload.namespace.create", "false", true},
		{"root-override", "workload.securityContext", map[string]any{"runAsUser": 0}, true},
		{"unsupported-controller-replicas", "workload.controller.replicas", 2, true},
		{"unsupported-controller-autoscaling", "workload.controller.autoscaling", map[string]any{"enabled": true}, true},
		{"pull-secret-string", "workload.imagePullSecrets", []string{"oci-auth"}, true},
		{"cross-namespace-pull-secret", "workload.imagePullSecrets", []any{map[string]any{"name": "oci-auth", "namespace": "application"}}, true},
		{"invalid-pull-secret", "workload.imagePullSecrets", []any{map[string]any{"name": "app/oci-auth"}}, true},
		{"duplicate-pull-secret", "workload.imagePullSecrets", []any{map[string]any{"name": "oci-auth"}, map[string]any{"name": "oci-auth"}}, true},
		{"zero-cpu", "workload.job.resources.limits.cpu", 0, true},
		{"bad-cpu-unit", "workload.job.resources.requests.cpu", "1Gi", true},
		{"negative-memory", "workload.job.resources.limits.memory", "-1Gi", true},
		{"missing-storage", "workload.job.resources.requests.ephemeral-storage", nil, true},
		{"gpu", "workload.job.resources.limits.nvidia.com/gpu", "1", true},
		{"unbounded-controller", "workload.controller.resources.limits.memory", nil, true},
		{"deadline-type", "workload.deadlineSeconds", "600", true},
		{"deadline-limit", "workload.deadlineSeconds", 1801, true},
		{"quota-type", "workload.quota.jobs", "8", true},
		{"empty-dns", "workload.dns.podSelector", nil, true},
		{"missing-certificate-secret", "workload.tls.existingSecret", "", true},
		{"invalid-key-path", "workload.tls.keyKey", "../tls.key", true},
		{"public-plaintext-token", "managedRemediation.registry.token", "plaintext", true},
		{"missing-registry", "managedRemediation.registry.url", "", true},
		{"registry-http", "managedRemediation.registry.url", "http://mirror.internal/npm", true},
		{"registry-type", "managedRemediation.registry.tokenEnabled", "true", true},
		{"missing-token-secret", "managedRemediation.registry.tokenEnabled", true, true},
		{"missing-ca-secret", "managedRemediation.registry.caEnabled", true, true},
		{"missing-npm-version", "managedRemediation.profile.npmVersion", "", true},
		{"floating-npm-version", "managedRemediation.profile.npmVersion", "latest", true},
		{"missing-node-version", "managedRemediation.profile.nodeVersion", "", true},
		{"relative-tool-path", "managedRemediation.profile.toolPath", "bin:/usr/bin", true},
		{"unknown-profile-key", "managedRemediation.profile.path", "/bin", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := chartValues()
			setChartValue(values, strings.Split(tc.path, "."), tc.value)
			for _, operation := range []string{"template", "lint"} {
				// Namespace inequality requires the real release context;
				// helm lint uses a synthetic release namespace on some versions.
				if operation == "lint" && !tc.schema {
					continue
				}
				var b []byte
				var err error
				if operation == "template" {
					b, err = renderChart(t, values, "1.36.0")
				} else {
					b, err = lintChart(t, values)
				}
				if err == nil {
					t.Fatalf("%s accepted unsafe %s", operation, tc.name)
				}
				lower := strings.ToLower(string(b))
				if tc.schema && !strings.Contains(lower, "schema") && !strings.Contains(lower, "[error] values.yaml:") {
					t.Fatalf("%s did not reject via schema: %s", operation, b)
				}
			}
		})
	}
}
func TestChartSchemaAllowsUnrelatedRoots(t *testing.T) {
	values := chartValues()
	values["operatorUnrelatedSetting"] = map[string]any{"retained": true}
	if b, err := lintChart(t, values); err != nil {
		t.Fatalf("unrelated root rejected: %v %s", err, b)
	}
}
