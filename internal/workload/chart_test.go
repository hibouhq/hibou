package workload

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func chartValues() map[string]any {
	return map[string]any{
		"hibou":              map[string]any{"baseURL": "https://hibou.internal"},
		"managedRemediation": map[string]any{"enabled": true, "registry": map[string]any{"url": "https://mirror.internal/npm"}, "profile": map[string]any{"npmVersion": "11.0.0", "nodeVersion": "22.0.0"}},
		"workload": map[string]any{
			"enabled": true, "runtimeValidated": true, "runtimeClassName": "sandbox",
			"image":    "mirror.internal/workload@sha256:" + strings.Repeat("a", 64),
			"caBundle": "-----BEGIN CERTIFICATE-----\npublic-test-ca\n-----END CERTIFICATE-----",
			"tls":      map[string]any{"existingSecret": "operator-broker-tls"},
		},
	}
}
func renderChart(t *testing.T, values map[string]any, version string) ([]byte, error) {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm unavailable")
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helm, "template", "security-test", filepath.Join("..", "..", "chart", "hibou"), "--namespace", "application", "--kube-version", version, "--values", "-")
	cmd.Stdin = bytes.NewReader(data)
	return cmd.CombinedOutput()
}
func decodeChart(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	d := yaml.NewDecoder(bytes.NewReader(data))
	var result []map[string]any
	for {
		var m map[string]any
		err := d.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(m) > 0 {
			result = append(result, m)
		}
	}
	return result
}
func nested(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		n, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = n[k]
	}
	return v
}
func TestChartSecureDeploymentAndAdmission(t *testing.T) {
	b, err := renderChart(t, chartValues(), "1.36.0")
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	objects := decodeChart(t, b)
	counts := map[string]int{}
	for _, o := range objects {
		kind, _ := o["kind"].(string)
		name, _ := nested(o, "metadata", "name").(string)
		if !strings.Contains(name, "workload") && !strings.Contains(name, "remediation") {
			continue
		}
		counts[kind]++
		switch kind {
		case "Namespace":
			if name == "application" || nested(o, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" {
				t.Fatal("missing separate PSA-restricted namespace")
			}
		case "Role":
			for _, r := range o["rules"].([]any) {
				rule := r.(map[string]any)
				for _, resource := range rule["resources"].([]any) {
					if resource != "jobs" && resource != "pods" {
						t.Fatal("forbidden RBAC resource")
					}
				}
				for _, verb := range rule["verbs"].([]any) {
					if verb != "create" && verb != "get" && verb != "list" && verb != "delete" {
						t.Fatal("forbidden RBAC verb")
					}
					if rule["resources"].([]any)[0] == "pods" {
						for _, verb := range rule["verbs"].([]any) {
							if verb == "create" || verb == "delete" {
								t.Fatal("unneeded Pod write permission")
							}
						}
					}
				}
			}
		case "RoleBinding":
			if nested(o, "metadata", "namespace") == "application" {
				t.Fatal("RoleBinding in API namespace")
			}
			subjects := o["subjects"].([]any)
			if len(subjects) != 1 || subjects[0].(map[string]any)["namespace"] != "application" || subjects[0].(map[string]any)["name"] != "security-test-hibou-workload-controller" {
				t.Fatal("wrong RBAC subject")
			}
		case "Deployment":
			if nested(o, "spec", "replicas") != 1 || nested(o, "spec", "strategy", "type") != "Recreate" || nested(o, "spec", "template", "spec", "serviceAccountName") != "security-test-hibou-workload-controller" {
				t.Fatal("unsafe controller concurrency/identity")
			}
			containers := nested(o, "spec", "template", "spec", "containers").([]any)
			c := containers[0].(map[string]any)
			command := c["command"].([]any)
			if len(command) != 2 || command[0] != "/usr/local/bin/hibou" || command[1] != "workload-controller" {
				t.Fatal("wrong launcher path")
			}
			env := map[string]any{}
			for _, v := range c["env"].([]any) {
				e := v.(map[string]any)
				env[e["name"].(string)] = e["value"]
			}
			if env["HIBOU_WORKLOAD_NAMESPACE"] != "security-test-hibou-workloads" || env["HIBOU_WORKLOAD_CONTROLLER_NAMESPACE"] != "application" || env["HIBOU_WORKLOAD_BROKER_URL"] != "https://security-test-hibou-workload-controller.application.svc:8443" || env["HIBOU_REMEDIATION_NPM_VERSION"] != "11.0.0" {
				t.Fatal("controller environment contract mismatch")
			}
		case "ValidatingAdmissionPolicy":
			if nested(o, "spec", "failurePolicy") != "Fail" {
				t.Fatal("admission does not fail closed")
			}
			raw, _ := json.Marshal(o)
			for _, required := range []string{"hostUsers", "65532", "RuntimeDefault", "allowPrivilegeEscalation", "readOnlyRootFilesystem", "capabilities.drop", "sha256:", "HIBOU_WORKLOAD_TOKEN", "metadata.uid", "emptyDir", "oldObject.spec", "resources.requests", "resources.limits", "runtimeClassName", "serviceAccountName"} {
				if !strings.Contains(string(raw), required) {
					t.Fatalf("missing admission constraint %s", required)
				}
			}
			if !strings.Contains(string(raw), "variables.p.activeDeadlineSeconds") {
				t.Fatal("Pod runtime bound missing from immutable admission")
			}
			if strings.HasSuffix(name, "-job") && !strings.Contains(string(raw), "request.operation != 'CREATE' || request.userInfo.username") {
				t.Fatal("Job metadata/finalizer maintenance must not require workload-controller identity")
			}
		case "ValidatingAdmissionPolicyBinding":
			if nested(o, "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "security-test-hibou-workloads" {
				t.Fatal("admission namespace can be bypassed")
			}
			if o["spec"].(map[string]any)["validationActions"].([]any)[0] != "Deny" {
				t.Fatal("admission only audits")
			}
		case "NetworkPolicy":
			if strings.HasSuffix(name, "-deny") {
				if len(nested(o, "spec", "podSelector").(map[string]any)) != 0 || len(nested(o, "spec", "ingress").([]any)) != 0 || len(nested(o, "spec", "egress").([]any)) != 0 {
					t.Fatal("execution namespace must deny all ingress/egress by default")
				}
			}
			if strings.HasSuffix(name, "-broker") {
				egress := nested(o, "spec", "egress").([]any)
				peer := egress[0].(map[string]any)["to"].([]any)[0].(map[string]any)
				if len(peer) != 2 || nested(peer, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "application" || nested(peer, "podSelector", "matchLabels", "app.kubernetes.io/component") != "workload-controller" {
					t.Fatal("broker selector must use namespace AND pod")
				}

			}
		}
	}
	for k, want := range map[string]int{"Namespace": 1, "Role": 1, "RoleBinding": 1, "Deployment": 1, "ValidatingAdmissionPolicy": 2, "ValidatingAdmissionPolicyBinding": 2, "ServiceAccount": 2} {
		if counts[k] != want {
			t.Fatalf("%s count %d want %d", k, counts[k], want)
		}
	}
	for _, o := range objects {
		if o["kind"] == "Deployment" && nested(o, "metadata", "name") == "security-test-hibou" && nested(o, "spec", "template", "spec", "automountServiceAccountToken") != false {
			t.Fatal("API received Kubernetes credentials")
		}
	}
}
func TestChartDisabledAndExistingNamespace(t *testing.T) {
	values := chartValues()
	values["workload"].(map[string]any)["enabled"] = false
	b, err := renderChart(t, values, "1.32.0")
	if err != nil {
		t.Fatalf("%s %v", b, err)
	}
	for _, o := range decodeChart(t, b) {
		if strings.Contains(nested(o, "metadata", "name").(string), "workload-controller") {
			t.Fatal("disabled feature rendered authority")
		}
	}
	values = chartValues()
	values["workload"].(map[string]any)["namespace"] = map[string]any{"name": "existing-execution", "create": false}
	b, err = renderChart(t, values, "1.33.0")
	if err != nil {
		t.Fatalf("%s %v", b, err)
	}
	var binding bool
	for _, o := range decodeChart(t, b) {
		if o["kind"] == "Namespace" {
			t.Fatal("existing namespace recreated")
		}
		if o["kind"] == "ValidatingAdmissionPolicyBinding" {
			binding = true
			if nested(o, "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "existing-execution" {
				t.Fatal("existing namespace admission missing")
			}
		}
	}
	if !binding {
		t.Fatal("existing namespace lacks admission binding")
	}
}
func TestChartFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		value     any
		version   string
	}{
		{"runtime", "runtimeClassName", "", "1.36.0"}, {"qualification", "runtimeValidated", false, "1.36.0"},
		{"image", "image", "mirror/tool:latest", "1.36.0"}, {"ca", "caBundle", "", "1.36.0"},
		{"tls", "tls", map[string]any{"existingSecret": ""}, "1.36.0"},
		{"namespace", "namespace", map[string]any{"name": "application"}, "1.36.0"},
		{"deadline", "deadlineSeconds", 1801, "1.36.0"}, {"old-cluster", "", "", "1.32.0"}, {"future-cluster", "", "", "1.37.0"},
		{"dns", "dns", map[string]any{"podSelector": nil}, "1.36.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := chartValues()
			if tc.key != "" {
				values["workload"].(map[string]any)[tc.key] = tc.value
			}
			b, err := renderChart(t, values, tc.version)
			if err == nil {
				t.Fatalf("insecure chart rendered: %s", b)
			}
		})
	}
}
